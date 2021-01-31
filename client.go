package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	_ "crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/vzex/dog-tunnel/common"
	"github.com/vzex/dog-tunnel/pipe"
	"github.com/vzex/dog-tunnel/platform"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path"
	"strings"
	"sync/atomic"
	//de "runtime/debug"
	//"runtime/pprof"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const (
	eAuthfail = byte(iota)
	eCollect
	eInit_enc
	eAuth
	eInit_action
	eInit_action_back
	eShowandquit
	eReady
	eReadyback
	eReverse
	eSettimeout
	eTunnel_error
	eTunnel_msg_s
	eTunnel_close_s
	eTunnel_msg_c
	eTunnel_msg_c_udp
	eTunnel_close
	eTunnel_open
	eTunnel_msg_s_head
	eInit_smartN
	eTunnel_msg_c_udp_sock
	eTunnel_msg_s_udp_sock
)

//var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
const WriteBufferSize = pipe.WriteBufferSize

var authKey = flag.String("auth", "", "cs: key for auth")
var pipeN = flag.Int("pipe", 1, "c: pipe num")
var bTcp = flag.Bool("tcp", false, "cs: use tcp to replace udp")
var xorData = flag.String("xor", "", "cs: xor key,c/s must use a some key")
var kcpSettings = flag.String("kcp", "", "cs: k1:v1;k2:v2;... k in (nodelay, resend, nc, snd, rcv, mtu),two sides should use the same setting")
var dataShards = flag.Int("ds", 0, "c: dataShards for fec, only available in udp mode")
var parShards = flag.Int("ps", 0, "c: pariryShards for fec, only available in udp mode")
var bCompress = flag.Bool("compress", false, "c: whether compress data, only available in udp mode")

var serviceAddr = flag.String("service", "", "cs: listen addr for client connect")
var localAddr = flag.String("local", "", "c: if local not empty, treat me as client, this is the addr for local listen, otherwise, treat as server,use \"udp:\" ahead, open udp port")
var remoteAction = flag.String("action", "", "c|s: for client to control server, if action is socks5,remote is socks5 server, if is addr like 127.0.0.1:22, remote server is a port redirect server, can use \"udp:\" ahead,\"route\" is for transparent socks, client default socks5, server default empty,if server's action is not empty, it will force clients's action=server's action")
var bVerbose = flag.Bool("v", false, "c|s: verbose mode")
var bShowVersion = flag.Bool("version", false, "c|s: show version")
var bEncrypt = flag.Bool("encrypt", false, "c: p2p mode encrypt")
var bconfuse = flag.Bool("confusion", false, "c: p2p mode confusion")
var dnsCacheNum = flag.Int("dnscache", 0, "c|s: if > 0, dns will cache xx minutes")
var timeOut = flag.Int("timeout", 100, "c: udp pipe set timeout(seconds)")
var smartCount = flag.Int("smartN", 0, "c: if >0, smart mode open(just for socks5 or route mode),it means how many requests of the same url at least are needed for sys to decide whether request going locally or remotely")

var bDebug = flag.Int("debug", 0, "c|s: more output log")
var bReverse = flag.Bool("r", false, "c: reverse mode, if true, client 's \"-local\" address will be listened on server side")
var sessionTimeout = flag.Int("session_timeout", 0, "c: if > 0, session will check itself if it's alive, if no msg tranfer for some seconds, socket will be closed, use this to avoid of zombie tcp sockets")
var bCache = flag.Bool("cache", false, "c: (valid in socks5 mode)if cache is true,save files requested with GET method into cache/ dir,cache request not pass through server side,no support for https")
var bSrc = flag.Bool("src", false, "c: whether logging src ip, just for tcp redirection")
var routeN = flag.Int("routen", 1, "c: threads(os-threads) num for route mode to parse real-addr")
var socks5Bind = flag.String("s5bind", "", "c: bind socks5 outbound socket to ADDRESS(interface/ip/hostname)")
var socks5BindIP net.IP // empty byte array

var clientType = 1
var currReadyId int32 = 0

type reqArg struct {
	url   string
	host  string
	times int
}

var cacheChan chan reqArg

var pipen int32 = 0

func getKcpSetting() *pipe.KcpSetting {
	setting := pipe.DefaultKcpSetting()
	//bSetResend := false
	if *kcpSettings != "" {
		arr := strings.Split(*kcpSettings, ";")
		for _, v := range arr {
			_arr := strings.Split(v, ":")
			if len(_arr) == 2 {
				k := _arr[0]
				var val int32
				var _val int
				_val, _ = strconv.Atoi(_arr[1])
				val = int32(_val)

				switch k {
				case "nodelay":
					setting.Nodelay = val
				case "resend":
					setting.Resend = val
					//bSetResend = true
				case "nc":
					setting.Nc = val
				case "snd":
					setting.Sndwnd = val
				case "rcv":
					setting.Rcvwnd = val
				case "mtu":
					setting.Mtu = val
				}
			}
		}
	}
	setting.Xor = *xorData
	/*
		if *dataShards > 0 && *parShards > 0 {
			if !bSetResend {
				setting.Resend = 0
				println("resend default to 0 in fec mode")
			}
		}
	*/
	return setting
}

func clientReport(r int, bSmart bool) {
	if r >= 0 {
		_pipen := atomic.AddInt32(&pipen, 1)
		if _pipen == int32(*pipeN) {
			g_ClientMapLock.RLock()
			client, bHave := g_ClientMap[*serviceAddr]
			g_ClientMapLock.RUnlock()
			if bHave {
				client.pipesLock.RLock()
				pipeInfo, bH := client.pipes[r]
				client.pipesLock.RUnlock()
				if !bH {
					log.Println("error!,no pipe", r)
					client.Quit()
				} else {
					readyIndex = r
					common.WriteCrypt(pipeInfo.conn, -1, eReady, []byte{}, client.encode)
				}
			}
		}
	} else {
		_pipen := atomic.AddInt32(&pipen, -1)
		if _pipen <= 0 {
			atomic.StoreInt32(&pipen, 0)
			g_ClientMapLock.RLock()
			client, bHave := g_ClientMap[*serviceAddr]
			g_ClientMapLock.RUnlock()
			if bHave {
				if !bSmart {
					client.Quit()
				}
			}
		}
	}
}

type _time struct {
	time.Time
	sync.RWMutex
}

var timeNow *_time

func (t *_time) now() time.Time {
	t.RLock()
	n := t.Time
	t.RUnlock()
	return n
}

type dnsInfo struct {
	Ip                  net.IP
	Status              string
	Queue               []*dnsQueryReq
	overTime, cacheTime int64
}

func debug(args ...interface{}) {
	if *bDebug > 1 {
		log.Println(args...)
	}
}

func (u *dnsInfo) IsAlive() bool {
	return timeNow.now().Unix() < u.overTime
}

func (u *dnsInfo) SetCacheTime(t int64) {
	if t >= 0 {
		u.cacheTime = t
	} else {
		t = u.cacheTime
	}
	u.overTime = t + timeNow.now().Unix()
}

func (u *dnsInfo) GetCacheTime() int64 {
	return u.overTime
}

func (u *dnsInfo) DeInit() {}

var g_ClientMap map[string]*Client
var g_ClientMapLock sync.RWMutex
var markName = ""
var bForceQuit = false

var aesIV []byte

func initAesIV() {
	aesIV = make([]byte, aes.BlockSize)
	for i := 0; i < aes.BlockSize; i++ {
		aesIV[i] = byte(i)
	}
}

func checkUdp(s string) (string, bool, bool) {
	action := s
	bUdp := false
	smart := false
	if strings.HasPrefix(s, "udp:") {
		action = strings.TrimPrefix(action, "udp:")
		bUdp = true
	} else if s == "socks5_smart" {
		action = "socks5"
		smart = true
	} else if s == "route_smart" {
		action = "route"
		smart = true
	}

	return action, bUdp, smart
}

func getEncodeFunc(aesBlock cipher.Block) func([]byte) []byte {
	return func(s []byte) []byte {
		if aesBlock == nil {
			return s
		} else {
			padLen := aes.BlockSize - (len(s) % aes.BlockSize)
			l := len(s) + padLen
			tmp := make([]byte, l)
			copy(tmp, s)
			tmp[l-1] = byte(padLen)
			encryptText := make([]byte, l)
			mode := cipher.NewCBCEncrypter(aesBlock, aesIV)
			mode.CryptBlocks(encryptText, tmp)
			return encryptText
		}
	}
}

func getDecodeFunc(aesBlock cipher.Block) func([]byte) []byte {
	return func(s []byte) []byte {
		if aesBlock == nil {
			return s
		} else {
			srcLen := len(s)
			if srcLen < aes.BlockSize || srcLen%aes.BlockSize != 0 {
				return []byte{}
			}
			decryptText := make([]byte, srcLen)
			mode := cipher.NewCBCDecrypter(aesBlock, aesIV)
			mode.CryptBlocks(decryptText, s)
			paddingLen := int(decryptText[srcLen-1])
			if paddingLen > aes.BlockSize {
				return []byte{}
			}
			return decryptText[:srcLen-paddingLen]
		}
	}
}

func CreateMainClient(id string) *Client {
	client := &Client{id: id, bUdp: false, sessions: make(map[int]*clientSession), pipes: make(map[int]*pipeInfo), quit: make(chan struct{}), hostWayTbl: make(map[string]*hostWay)}
	client.smartN = *smartCount
	g_ClientMapLock.Lock()
	g_ClientMap[id] = client
	g_ClientMapLock.Unlock()
	if *sessionTimeout > 0 {
		go client.sessionCheckDie()
	}
	client.reverseAddr = *localAddr
	client.action, client.bUdp, client.bSmart = checkUdp(*remoteAction)
	if client.bSmart {
		if !*bReverse {
			go client.checkSmart()
			go client.MultiListen()
		}
	}
	return client
}
func CreateSessionAndLoop(bIsTcp bool, idindex int, bSmart bool) {
	CreateSession(bIsTcp, idindex, bSmart)
	dt := 3
	if bSmart {
		dt = 15
	}
	time.AfterFunc(time.Second*time.Duration(dt), func() {
		CreateSessionAndLoop(bIsTcp, idindex, bSmart)
	})
	log.Println("sys will reconnect pipe", idindex, "after "+strconv.Itoa(dt)+" seconds")
}

func CreateSession(bIsTcp bool, idindex int, bSmart bool) bool {
	var s_conn net.Conn
	var err error
	if bIsTcp {
		s_conn, err = net.DialTimeout("tcp", *serviceAddr, 30*time.Second)
	} else {
		setting := getKcpSetting()
		s_conn, err = pipe.DialTimeoutWithSetting(*serviceAddr, *timeOut, setting, *dataShards, *parShards, *bCompress, *bconfuse)
	}
	if err != nil {
		log.Println("try dial err", err.Error())
		return false
	}
	log.Println("try dial", *serviceAddr, "ok", idindex, s_conn.LocalAddr().String())
	id := *serviceAddr
	g_ClientMapLock.RLock()
	client, bHave := g_ClientMap[id]
	g_ClientMapLock.RUnlock()
	if !bHave {
		log.Println("can't find the client")
		client = CreateMainClient(*serviceAddr)
	}
	if *authKey != "" {
		log.Println("request auth key", *authKey)
		common.Write(s_conn, -1, eAuth, []byte(common.Xor(*authKey)))
	}
	if *bEncrypt {
		log.Println("request encrypt")
		encrypt_tail := client.encryptstr
		if encrypt_tail == "" {
			encrypt_tail = string([]byte(fmt.Sprintf("%d%d", int32(timeNow.now().Unix()), (rand.Intn(100000) + 100)))[:12])
			client.encryptstr = encrypt_tail
		}
		aesKey := "asd4" + encrypt_tail
		log.Println("debug aeskey", encrypt_tail)
		aesBlock, _ := aes.NewCipher([]byte(aesKey))
		common.Write(s_conn, -1, eInit_enc, []byte(common.Xor(encrypt_tail)))
		if client.encode == nil {
			client.SetCrypt(getEncodeFunc(aesBlock), getDecodeFunc(aesBlock))
		}
	}
	client.stimeout = *sessionTimeout
	common.WriteCrypt(s_conn, -1, eInit_action, []byte(*remoteAction), client.encode)
	if client.smartN > 0 {
		common.WriteCrypt(s_conn, -1, eInit_smartN, []byte(strconv.Itoa(client.smartN)), client.encode)
	}

	pinfo := &pipeInfo{conn: s_conn, total: 0, t: timeNow.now().Unix(), owner: nil, newindex: 0}
	client.pipesLock.Lock()
	client.pipes[idindex] = pinfo
	client.pipesLock.Unlock()
	clientReport(idindex, bSmart)
	callback := func(conn net.Conn, sessionId int, action byte, content []byte) {
		var msg string
		if client.decode != nil {
			msg = string(client.decode(content))
		} else {
			msg = string(content)
		}
		client.OnTunnelRecv(conn, sessionId, action, msg, pinfo)
	}
	if bIsTcp {
		common.Read(s_conn, callback)
	} else {
		common.ReadUDP(s_conn, callback, pipe.ReadBufferSize)
	}
	log.Println("remove pipe", idindex)
	clientReport(-1, bSmart)
	client.pipesLock.Lock()
	delete(client.pipes, idindex)
	client.pipesLock.Unlock()
	s_conn.Close()

	client.pipesLock.RLock()
	l := len(client.pipes)
	client.pipesLock.RUnlock()
	if l == 0 && !bSmart {
		client.Quit()
	}
	return true
}
func Listen(bIsTcp bool, addr string) bool {
	var err error
	if bIsTcp {
		g_LocalConnLock.Lock()
		g_LocalConn, err = net.Listen("tcp", addr)
		g_LocalConnLock.Unlock()
	} else {
		g_LocalConnLock.Lock()
		setting := getKcpSetting()
		g_LocalConn, err = pipe.ListenWithSetting(addr, setting)
		g_LocalConnLock.Unlock()
	}
	if err != nil {
		g_LocalConnLock.Lock()
		g_LocalConn = nil
		g_LocalConnLock.Unlock()
		log.Println("cannot listen addr:" + err.Error())
		return false
	}
	println("service start success,please connect", addr)
	for {
		conn, err := g_LocalConn.Accept()
		if err != nil {
			log.Println("server err:", err.Error())
			break
		}
		//log.Println("client", sc.id, "create session", sessionId)

		id := conn.RemoteAddr().String()
		if bIsTcp {
			log.Println("add tcp session", id)
		} else {
			log.Println("add udp session", id)
		}
		g_ClientMapLock.Lock()
		client, have := g_ClientMap[id]
		if !have {
			client = &Client{id: id, bUdp: false, sessions: make(map[int]*clientSession), pipes: make(map[int]*pipeInfo), quit: make(chan struct{}), hostWayTbl: make(map[string]*hostWay)}
			g_ClientMap[id] = client
			if *authKey == "" {
				client.authed = true
			}
		}
		g_ClientMapLock.Unlock()

		maxId := 0
		f := func(i int) {
			now := timeNow.now().Unix()
			client.pipes[i] = &pipeInfo{conn: conn, total: 0, t: now, owner: nil, newindex: 0}
		}
		client.pipesLock.Lock()
		for i, _ := range client.pipes {
			if maxId < i {
				maxId = i
			}
		}
		f(maxId + 1)
		client.pipesLock.Unlock()
		log.Println("add pipe", "for", maxId+1)
		go client.ServerProcess(bIsTcp, maxId+1)
	}
	g_LocalConnLock.Lock()
	g_LocalConn = nil
	g_LocalConnLock.Unlock()
	return true
}

func (client *Client) ServerProcess(bIsTcp bool, idindex int) {
	client.pipesLock.RLock()
	pipeInfo, _ := client.pipes[idindex]
	client.pipesLock.RUnlock()
	f := func() {
		if pipeInfo.owner != nil {
			old := client.id
			client.pipesLock.Lock()
			delete(client.pipes, idindex)
			l := len(client.pipes)
			client.pipesLock.Unlock()
			if l == 0 {
				client._Quit()
			}
			idindex = pipeInfo.newindex
			client = pipeInfo.owner
			pipeInfo.owner = nil
			log.Println(old, "pipe >>", client.id, idindex)
			client.pipesLock.RLock()
			pipeInfo, _ = client.pipes[idindex]
			client.pipesLock.RUnlock()
		}
	}
	callback := func(conn net.Conn, sessionId int, action byte, content []byte) {
		f()
		var msg string
		if client.decode != nil {
			msg = string(client.decode(content))
		} else {
			msg = string(content)
		}
		client.OnTunnelRecv(conn, sessionId, action, msg, pipeInfo)
	}
	conn := pipeInfo.conn
	if bIsTcp {
		common.Read(conn, callback)
	} else {
		common.ReadUDP(conn, callback, pipe.ReadBufferSize)
	}
	f()
	client.pipesLock.Lock()
	delete(client.pipes, idindex)
	l := len(client.pipes)
	client.pipesLock.Unlock()
	conn.Close()
	if bIsTcp {
		log.Println("remove tcp pipe", idindex, "for", client.id)
	} else {
		log.Println("remove udp pipe", idindex, "for", client.id)
	}
	if l == 0 {
		client.Quit()
	}
}

type fileSetting struct {
	Key string
}

func saveSettings(info fileSetting) error {
	clientInfoStr, err := json.Marshal(info)
	if err != nil {
		return err
	}
	user, err := user.Current()
	if err != nil {
		return err
	}
	filePath := path.Join(user.HomeDir, ".dtunnel")

	return ioutil.WriteFile(filePath, clientInfoStr, 0700)
}

func loadSettings(info *fileSetting) error {
	user, err := user.Current()
	if err != nil {
		return err
	}
	filePath := path.Join(user.HomeDir, ".dtunnel")
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return err
	}
	err = json.Unmarshal([]byte(content), info)
	if err != nil {
		return err
	}
	return nil
}

var checkDns chan *dnsQueryReq
var checkDnsRes chan *dnsQueryBack
var checkRealAddrChan chan *queryRealAddrInfo

type dnsQueryReq struct {
	c    chan *dnsQueryRes
	host string
}

type dnsQueryBack struct {
	host   string
	status string
	ip     net.IP
	err    error
}

type dnsQueryRes struct {
	err error
	ip  net.IP
}

type queryRealAddrInfo struct {
	conn net.Conn
	c    chan string
}

func checkRealAddr() {
	for {
		select {
		case info := <-checkRealAddrChan:
			remote := platform.GetDestAddrFromConn(info.conn)
			info.c <- remote
		}
	}
}

func dnsLoop() {
	t := time.NewTicker(time.Second * 15)
	defer func() {
		t.Stop()
	}()
	for {
		select {
		case <-t.C:
			common.UpdateCacheMgr()
		case info := <-checkDns:
			cache := common.GetCacheContainer("dns")
			cacheInfo := cache.GetCache(info.host)
			if cacheInfo == nil {
				cache.AddCache(info.host, &dnsInfo{Queue: []*dnsQueryReq{info}, Status: "querying"}, int64(*dnsCacheNum*60))
				go func() {
					back := &dnsQueryBack{host: info.host}
					//log.Println("try dial", info.host)
					ip, err := net.LookupIP(info.host)
					//log.Println("try dial", info.host, "ok")
					if err != nil {
						back.status = "queryfail"
						back.err = err
					} else if len(ip) > 0 {
						back.status = "queryok"
						back.ip = ip[0]
					} else {
						back.status = "queryfail"
						back.err = errors.New("empty ip")
					}
					checkDnsRes <- back
				}()
			} else {
				_cacheInfo := cacheInfo.(*dnsInfo)
				debug("on trigger", info.host, _cacheInfo.GetCacheTime(), len(_cacheInfo.Queue))
				switch _cacheInfo.Status {
				case "querying":
					_cacheInfo.Queue = append(_cacheInfo.Queue, info)
					//cache.UpdateCache(info.host, _cacheInfo)
					cacheInfo.SetCacheTime(-1)
				case "queryok":
					cacheInfo.SetCacheTime(-1)
					go func() {
						info.c <- &dnsQueryRes{ip: _cacheInfo.Ip}
					}()
				}
				//url = cacheInfo.(*dnsInfo).Ip + fmt.Sprintf(":%d", info.port)
			}
		case info := <-checkDnsRes:
			cache := common.GetCacheContainer("dns")
			cacheInfo := cache.GetCache(info.host)
			if cacheInfo != nil {
				_cacheInfo := cacheInfo.(*dnsInfo)
				_cacheInfo.Status = info.status
				switch info.status {
				case "queryfail":
					for _, _info := range _cacheInfo.Queue {
						c := _info.c
						go func() {
							c <- &dnsQueryRes{err: info.err}
						}()
					}
					cache.DelCache(info.host)
				case "queryok":
					log.Println("add host", info.host, "to dns cache")
					_cacheInfo.Ip = info.ip
					_cacheInfo.SetCacheTime(-1)
					debug("process the queue of host", info.host, len(_cacheInfo.Queue))
					for _, _info := range _cacheInfo.Queue {
						c := _info.c
						go func() {
							c <- &dnsQueryRes{ip: _cacheInfo.Ip}
						}()
					}
					_cacheInfo.Queue = []*dnsQueryReq{}
				}
				//cache.UpdateCache(info.host, _cacheInfo)
			}
		}
	}
}

var readyIndex int = 0

func main() {
	flag.Parse()
	/*if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}*/
	timeNow = &_time{}
	go func() {
		for _ = range time.Tick(time.Second) {
			timeNow.Lock()
			timeNow.Time = time.Now()
			timeNow.Unlock()
		}
	}()
	if *bCache {
		cacheChan = make(chan reqArg)
		go handleUrl()
	}
	timeNow.Lock()
	timeNow.Time = time.Now()
	timeNow.Unlock()
	rand.Seed(time.Now().Unix())
	checkDns = make(chan *dnsQueryReq)
	checkDnsRes = make(chan *dnsQueryBack)
	checkRealAddrChan = make(chan *queryRealAddrInfo)
	go dnsLoop()
	if *bShowVersion {
		fmt.Printf("%.2f\n", common.Version)
		return
	}
	if !*bVerbose {
		log.SetOutput(ioutil.Discard)
	}
	if *serviceAddr == "" {
		println("you must assign service arg")
		return
	}
	if *localAddr == "" {
		clientType = 0
	}
	if *dataShards < 0 || *dataShards >= 128 {
		println("-ds should in [0-127]")
		return
	}
	if *parShards < 0 || *parShards >= 128 {
		println("-ds should in [0-127]")
		return
	}
	if *remoteAction == "" && clientType == 1 {
		*remoteAction = "socks5"
	}
	if *socks5Bind != "" && *remoteAction == "socks5" {
		socks5BindIP = common.ParseIP(*socks5Bind)
		if socks5BindIP != nil {
			log.Println("socks5 bind to ip:", socks5BindIP.String())
		}
	} else {
		*socks5Bind = ""
	}
	if *smartCount > 0 {
		if *remoteAction == "socks5" || *remoteAction == "route" {
			*remoteAction += "_smart"
		} else {
			log.Println("not support smart mode for", *remoteAction)
		}
	}
	_, bUdp, _ := checkUdp(*remoteAction)
	if bUdp && *sessionTimeout == 0 {
		println("you must assign session_timeout arg")
		return
	}
	if *bEncrypt {
		if clientType != 1 {
			println("only client side need encrypt")
			return
		}
	}
	if *remoteAction == "" && clientType == 1 {
		println("must have action")
		return
	}
	initAesIV()
	if *xorData != "" {
		common.XorSetKey(*xorData)
	}
	threadN := *routeN
	if threadN < 1 {
		threadN = 1
	}
	for i := 0; i < threadN; i++ {
		go checkRealAddr()
	}
	g_ClientMapLock.Lock()
	g_ClientMap = make(map[string]*Client)
	g_ClientMapLock.Unlock()
	if *bDebug > 0 {
		go func() {
			c := time.NewTicker(time.Second * 15)
			for _ = range c.C {
				log.Println("begin =====")
				now := timeNow.now().Unix()
				g_ClientMapLock.RLock()
				for addr, client := range g_ClientMap {
					var rate float64 = 0
					client.pipesLock.RLock()
					for _, pipeInfo := range client.pipes {
						pipeInfo.RLock()
						dt := now - pipeInfo.t
						if dt <= 0 {
							dt = 1
						}
						_rate := float64(pipeInfo.total) / float64(dt)
						if dt > 60 {
							_rate = 0
							dt = 1
						}
						rate += _rate
						log.Println("pipe info", _rate, pipeInfo.total, dt)
						pipeInfo.RUnlock()
					}
					log.Println("----", addr, len(client.pipes), "pipes;", len(client.sessions), "sessions;", int64(rate), "bytes/second;")
					client.pipesLock.RUnlock()
				}
				g_ClientMapLock.RUnlock()
				log.Println("end =====")
			}
			g_LocalConnLock.RLock()
			if g_LocalConn != nil && *bTcp {
				g_LocalConn.(*pipe.Listener).Dump()
			}
			g_LocalConnLock.RUnlock()
		}()
	}
	var w sync.WaitGroup
	w.Add(2)
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		n := 0
		f := func() {
			<-c
			/*if clientType == 1 {
				for _, client := range g_ClientMap {
					for i, pipe := range client.pipes {
						pipe.Close()
						log.Println("close pipe", i)
						break
					}
				}
			} else {
				for addr, client := range g_ClientMap {
					for i, _ := range client.pipes {
						log.Println("show pipe", addr, i)
					}
				}
			}*/
			n++
			if n > 2 {
				log.Println("force shutdown")
				os.Exit(-1)
			}
			log.Println("received signal,shutdown")
			bForceQuit = true
			_map := g_ClientMap
			for _, client := range _map {
				client.Quit()
			}
			atomic.StoreInt32(&pipen, 0)
			g_LocalConnLock.RLock()
			if g_LocalConn != nil {
				g_LocalConn.Close()
			}
			g_LocalConnLock.RUnlock()
		}
		f()
		go func() {
			for {
				f()
			}
		}()
		w.Done()
	}()

	loop := func() {
		if clientType == 0 {
			Listen(*bTcp, *serviceAddr)
			if !bForceQuit {
				w.Done()
			}
			w.Done()
		} else {
			id := *serviceAddr
			g_ClientMapLock.RLock()
			client, bHave := g_ClientMap[id]
			g_ClientMapLock.RUnlock()
			if !bHave {
				client = CreateMainClient(id)
			}
			for i := 0; i < *pipeN; i++ {
				go CreateSessionAndLoop(*bTcp, i, client.bSmart)
			}
			w.Done()
		}
	}
	loop()
	w.Wait()
	log.Println("service shutdown")
}

type clientSession struct {
	pipe            *pipeInfo
	localConn       net.Conn
	localUdpConn    *net.UDPConn
	localUdpAddr    *net.UDPAddr
	connLock        sync.RWMutex
	udpConnLock     sync.RWMutex
	status          string
	recvMsg         string
	extra           uint8
	dieT            time.Time
	hash            string
	decide          decideStatus
	decideLock      sync.RWMutex
	cacheMsg        string
	udpCacheMsg     []string
	cacheLock       sync.RWMutex
	headSendN       int32
	headFailN       int32
	tunnelN         int32
	closeN          int32
	udpAddr         string
	realUdpAddr     *net.UDPAddr
	responseUdpAddr *net.UDPAddr
	sm              *smartSession
	listenerUdp     *net.UDPConn
}

func (session *clientSession) processSockProxy(content string, callback func([]byte, string, reqMsg)) {
	session.recvMsg += content
	bytes := []byte(session.recvMsg)
	size := len(bytes)
	//log.Println("recv msg-====", len(session.recvMsg),  session.status)
	switch session.status {
	case "init":
		if size < 2 {
			//println("wait init")
			return
		}
		var _, nmethod uint8 = bytes[0], bytes[1]
		session.status = "version"
		session.recvMsg = string(bytes[2:])
		session.extra = nmethod
	case "version":
		if uint8(size) < session.extra {
			//println("wait version")
			return
		}
		var send = []uint8{5, 0}
		session.localConn.Write(send)
		session.status = "hello"
		session.recvMsg = string(bytes[session.extra:])
		session.extra = 0
	case "hello":
		var hello reqMsg
		bOk, tail := hello.read(bytes)
		if bOk {
			session.status = "ok"
			session.recvMsg = string(tail)
			callback(bytes, hello.url, hello)
		}
		return
	case "ok":
		return
	}
	session.processSockProxy("", callback)
}

type ansMsg struct {
	ver  uint8
	rep  uint8
	rsv  uint8
	atyp uint8
	buf  []uint8
	mlen uint16
}

func (msg *ansMsg) gen_withbytes(req *reqMsg, rep uint8, addr []byte) {
	msg.mlen = uint16(3 + len(addr))
	msg.buf = make([]byte, msg.mlen)

	msg.buf[0], msg.buf[1], msg.buf[2] = 0, 0, 0
	for i := 0; i < len(addr); i++ {
		msg.buf[i+3] = addr[i]
	}
}
func (msg *ansMsg) gen(req *reqMsg, rep uint8, addr string) {
	msg.ver = 5
	msg.rep = rep //rfc1928
	msg.rsv = 0
	msg.atyp = 1 //req.atyp

	msg.mlen = 10
	msg.buf = make([]byte, msg.mlen)
	msg.buf[0], msg.buf[1], msg.buf[2], msg.buf[3] = msg.ver, msg.rep, msg.rsv, msg.atyp
	if addr != "" {
		arr := strings.Split(addr, ":")
		var ip string
		var port int
		switch len(arr) {
		case 0, 1:
			break
		case 2:
			ip = arr[0]
			port, _ = strconv.Atoi(arr[1])
			if ip == "" {
				ip = "127.0.0.1"
			}
			_ip := net.ParseIP(ip).To4()
			for i := 0; i < 4; i++ {
				msg.buf[4+i] = _ip[i]
			}
			msg.buf[9] = byte(port)
			msg.buf[8] = byte(port >> 8)
			return
		default:
		}
	} else {
		for i := 4; i < 10; i++ {
			msg.buf[i] = 0
		}
	}
}

type reqMsg struct {
	ver       uint8     // socks v5: 0x05
	cmd       uint8     // CONNECT: 0x01, BIND:0x02, UDP ASSOCIATE: 0x03
	rsv       uint8     //RESERVED
	atyp      uint8     //IP V4 addr: 0x01, DOMANNAME: 0x03, IP V6 addr: 0x04
	dst_addr  [255]byte //
	dst_port  [2]uint8  //
	dst_port2 uint16    //

	reqtype string
	url     string
}

func (msg *reqMsg) read(bytes []byte) (bool, []byte) {
	size := len(bytes)
	if size < 4 {
		return false, bytes
	}
	buf := bytes[0:4]

	msg.ver, msg.cmd, msg.rsv, msg.atyp = buf[0], buf[1], buf[2], buf[3]
	//println("test", msg.ver, msg.cmd, msg.rsv, msg.atyp)

	if 5 != msg.ver || 0 != msg.rsv {
		log.Println("Request Message VER or RSV error!")
		return false, bytes[4:]
	}
	buf = bytes[4:]
	size = len(buf)
	switch msg.atyp {
	case 1: //ip v4
		if size < 4 {
			return false, buf
		}
		copy(msg.dst_addr[:4], buf[:4])
		buf = buf[4:]
		size = len(buf)
	case 4:
		if size < 16 {
			return false, buf
		}
		copy(msg.dst_addr[:16], buf[:16])
		buf = buf[16:]
		size = len(buf)
	case 3:
		if size < 1 {
			return false, buf
		}
		copy(msg.dst_addr[:1], buf[:1])
		buf = buf[1:]
		size = len(buf)
		if size < int(msg.dst_addr[0]) {
			return false, buf
		}
		copy(msg.dst_addr[1:], buf[:int(msg.dst_addr[0])])
		buf = buf[int(msg.dst_addr[0]):]
		size = len(buf)
	}
	if size < 2 {
		return false, buf
	}
	copy(msg.dst_port[:], buf[:2])
	msg.dst_port2 = (uint16(msg.dst_port[0]) << 8) + uint16(msg.dst_port[1])

	switch msg.cmd {
	case 1:
		msg.reqtype = "tcp"
	case 2:
		log.Println("BIND")
	case 3:
		msg.reqtype = "udp"
	}
	switch msg.atyp {
	case 1: // ipv4
		msg.url = fmt.Sprintf("%d.%d.%d.%d:%d", msg.dst_addr[0], msg.dst_addr[1], msg.dst_addr[2], msg.dst_addr[3], msg.dst_port2)
	case 3: //DOMANNAME
		msg.url = net.JoinHostPort(string(msg.dst_addr[1:1+msg.dst_addr[0]]), fmt.Sprintf("%d", msg.dst_port2))
	case 4: //ipv6
		msg.url = fmt.Sprintf("[%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x]:%d", msg.dst_addr[0], msg.dst_addr[1], msg.dst_addr[2], msg.dst_addr[3],
			msg.dst_addr[4], msg.dst_addr[5], msg.dst_addr[6], msg.dst_addr[7],
			msg.dst_addr[8], msg.dst_addr[9], msg.dst_addr[10], msg.dst_addr[11],
			msg.dst_addr[12], msg.dst_addr[13], msg.dst_addr[14], msg.dst_addr[15],
			msg.dst_port2)
	}
	log.Println(msg.reqtype, msg.url, msg.atyp, msg.dst_port2)
	return true, buf[2:]
}

type pipeInfo struct {
	conn     net.Conn
	total    int64
	t        int64
	owner    *Client
	newindex int
	sync.RWMutex
}

func (pinfo *pipeInfo) Add(size, now int64) {
	pinfo.Lock()
	defer pinfo.Unlock()
	if now-pinfo.t > 60 {
		pinfo.total = size
		pinfo.t = now
	} else {
		pinfo.total += size
	}
}

type Client struct {
	id             string
	buster         bool
	pipes          map[int]*pipeInfo // client for pipes
	pipesLock      sync.RWMutex
	sessions       map[int]*clientSession // session to pipeid
	sessionLock    sync.RWMutex
	bUdp           bool
	action         string
	closed         int32
	encode, decode func([]byte) []byte
	authed         bool
	localconn      net.Conn
	listener       net.Listener
	listenerUdp    *net.UDPConn
	reverseAddr    string
	readyId        string
	newindex       int
	encryptstr     string
	stimeout       int
	quit           chan struct{}
	bSmart         bool

	hostWayTbl  map[string]*hostWay
	hostWayLock sync.RWMutex

	closeLock sync.RWMutex

	smartN int
}

// pipe : client to client
// local : client to local apps

func (sc *Client) setSessionUdpConn(sessionId int, conn *net.UDPConn) *clientSession {
	if sessionId < 0 {
		return nil
	}
	sc.closeLock.RLock()
	defer sc.closeLock.RUnlock()
	if sc.closed == 1 {
		return nil
	}
	sc.sessionLock.RLock()
	defer sc.sessionLock.RUnlock()
	session, bHave := sc.sessions[sessionId]
	if bHave {
		session.udpConnLock.Lock()
		if session.localUdpConn != nil {
			session.localUdpConn.Close()
		}
		session.localUdpConn = conn
		session.udpConnLock.Unlock()
		return session
	} else {
		return nil
	}
}
func (sc *Client) setSessionConn(sessionId int, conn net.Conn) *clientSession {
	if sessionId < 0 {
		return nil
	}
	sc.closeLock.RLock()
	defer sc.closeLock.RUnlock()
	if sc.closed == 1 {
		return nil
	}
	sc.sessionLock.RLock()
	defer sc.sessionLock.RUnlock()
	session, bHave := sc.sessions[sessionId]
	if bHave {
		session.connLock.Lock()
		if session.localConn != nil {
			session.localConn.Close()
		}
		session.localConn = conn
		session.connLock.Unlock()
		return session
	} else {
		return nil
	}
}

func (sc *Client) getSession(sessionId int) *clientSession {
	if sessionId < 0 {
		return nil
	}
	sc.sessionLock.RLock()
	defer sc.sessionLock.RUnlock()
	session, bHave := sc.sessions[sessionId]
	if bHave {
		closed := false
		sc.closeLock.RLock()
		closed = (sc.closed == 1)
		sc.closeLock.RUnlock()
		if closed {
			return nil
		}
		return session
	} else {
		return nil
	}
}

func (sc *Client) removeSession(sessionId int) bool {
	sc.sessionLock.Lock()
	defer sc.sessionLock.Unlock()
	common.RmId("session", sessionId)
	session, bHave := sc.sessions[sessionId]
	//log.Println("remove s", sessionId, bHave)
	if bHave {
		if session.listenerUdp != nil {
			session.listenerUdp.Close()
		}
		delete(sc.sessions, sessionId)
		session.connLock.Lock()
		if session.localConn != nil {
			//log.Println("remove s2", session.localConn.RemoteAddr().String(), sessionId)
			session.localConn.Close()
			session.localConn = nil
		}
		session.connLock.Unlock()
		session.udpConnLock.Lock()
		if session.localUdpConn != nil {
			session.localUdpConn.Close()
			//log.Println("remove s2", session.localUdpConn.LocalAddr().String(), sessionId)
			session.localUdpConn = nil
		}
		session.udpConnLock.Unlock()
	}
	return bHave
}

func (sc *Client) createSession(sessionId int, session *clientSession) int {
	if sessionId == -1 {
		sessionId = common.GetId("session")
	}
	sc.sessionLock.Lock()
	defer sc.sessionLock.Unlock()
	old, bHave := sc.sessions[sessionId]
	if bHave {
		old.connLock.Lock()
		if old.localConn != nil {
			old.localConn.Close()
			old.localConn = nil
		}
		old.connLock.Unlock()
		old.udpConnLock.Lock()
		if old.localUdpConn != nil {
			old.localUdpConn.Close()
			old.localUdpConn = nil
		}
		old.udpConnLock.Unlock()
	}
	sc.closeLock.RLock()
	if sc.closed == 1 {
		sc.closeLock.RUnlock()
		return -1
	}
	sc.sessions[sessionId] = session
	sc.closeLock.RUnlock()
	return sessionId
}

func DialTimeoutBind(network, address string, timeout time.Duration, bindIP net.IP) (net.Conn, error) {
	if len(bindIP) == 0 {
		return net.DialTimeout(network, address, timeout)
	}

	var d *net.Dialer
	switch network {
	case "tcp":
		a := &net.TCPAddr{IP: bindIP}
		d = &net.Dialer{Timeout: timeout, LocalAddr: a}
	case "udp":
		a := &net.UDPAddr{IP: bindIP}
		d = &net.Dialer{Timeout: timeout, LocalAddr: a}
	default:
		a := &net.IPAddr{IP: bindIP}
		d = &net.Dialer{Timeout: timeout, LocalAddr: a}
	}
	return d.Dial(network, address)
}

func (sc *Client) OnTunnelRecv(pipe net.Conn, sessionId int, action byte, content string, pinfo *pipeInfo) {
	debug("recv p2p tunnel", sessionId, action, len(content))
	session := sc.getSession(sessionId)
	var conn net.Conn
	if session != nil {
		session.connLock.RLock()
		conn = session.localConn
		session.connLock.RUnlock()
	}
	if clientType == 0 && !sc.authed && action != eCollect {
		if action != eAuth || common.Xor(content) != *authKey {
			log.Println("auth fail", action, common.Xor(content), *authKey, pipe.RemoteAddr().String())
			go common.Write(pipe, sessionId, eAuthfail, []byte{})
			return
		}
		sc.authed = true
		return
	}
	switch action {
	case eSettimeout:
		timeout, _ := strconv.Atoi(content)
		log.Println("set timeout", timeout)
	case eAuthfail:
		fmt.Println("auth key not eq")
		sc.Quit()
	case eTunnel_msg_s_udp_sock:
		//log.Println("recv from remote udp", sessionId, []byte(content))
		if session == nil {
			return
		}
		c := []byte(content)
		if session.listenerUdp != nil {
			//log.Println("client send back", len(c), c[:10], session.realUdpAddr, session.responseUdpAddr)
			session.listenerUdp.WriteToUDP(c, session.responseUdpAddr)
		}
	case eShowandquit:
		println(content)
		sc.Quit()
	case eTunnel_msg_s, eTunnel_msg_s_head:
		if sc.bUdp {
			if sc.listenerUdp != nil && session != nil {
				sc.listenerUdp.WriteToUDP([]byte(content), session.localUdpAddr)
			}
			return
		}
		//log.Println("recv from msg", action, len(content), sessionId)
		if conn != nil {
			normalDecide := func() decideStatus {
				session.decideLock.Lock()
				if NotDecide == session.decide {
					if pipe == nil {
						session.decide = DecideLocal
					} else {
						session.decide = DecideRemote
					}
					session.endSmartMonitor(sc, sessionId, pipe == nil)
				}
				d := session.decide
				session.decideLock.Unlock()
				return d
			}
			if action == eTunnel_msg_s_head && sc.bSmart {
				if []byte(content)[1] != 0 {
					way := session.checkDecide(pipe == nil)
					if atomic.AddInt32(&session.headFailN, 1) < session.tunnelN {
						return
					}
					if way != nil {
						session.decideLock.Lock()
						if NotDecide == session.decide {
							session.decide = way.getDecide()
						}
						session.decideLock.Unlock()
					}
				} else {
					if atomic.AddInt32(&session.headSendN, 1) > 1 {
						return
					}
					//normalDecide()
				}
			}
			f := func() {
				if sc.stimeout > 0 {
					session.dieT = timeNow.now().Add(time.Duration(sc.stimeout) * time.Second)
				}
				conn.Write([]byte(content))
				if pinfo != nil {
					pinfo.Add(int64(len(content)), timeNow.now().Unix())
				}
			}
			if sc.bSmart && action == eTunnel_msg_s {
				decide := normalDecide()
				if decide == DecideLocal && pipe == nil {
					//log.Println("socks5 local", len(content), sessionId)
					f()
				} else if decide == DecideRemote && pipe != nil {
					//log.Println("socks5 remote ", len(content), sessionId)
					f()
				}
			} else {
				f()
			}
		} else {
			//log.Println("cannot tunnel msg", sessionId)
		}
		/*
			case eTunnel_error:
				log.Println("tunnel error", content, sessionId)
				go sc.removeSession(sessionId)*/
	case eTunnel_error, eTunnel_close_s:
		if session != nil {
			if !sc.bSmart {
				go sc.removeSession(sessionId)
				return
			}
			session.decideLock.RLock()
			decide := session.decide
			session.decideLock.RUnlock()
			//log.Println("try close session", n, sessionId, decide, pipe == nil)
			if atomic.AddInt32(&session.closeN, 1) >= session.tunnelN {
				go sc.removeSession(sessionId)
			} else if decide == DecideLocal && pipe == nil {
				go sc.removeSession(sessionId)
			} else if decide == DecideRemote && pipe != nil {
				go sc.removeSession(sessionId)
			}
		}
	case eInit_action_back:
		log.Println("server force do action", content)
		sc.action, sc.bUdp, sc.bSmart = checkUdp(content)
	case eInit_action:
		sc.action = content
		log.Println("init action", content)
		sc.action, sc.bUdp, sc.bSmart = checkUdp(content)
		if *remoteAction != "" && *remoteAction != sc.action {
			sc.action, sc.bUdp, sc.bSmart = checkUdp(*remoteAction)
			go common.WriteCrypt(pipe, sessionId, eInit_action_back, []byte(*remoteAction), sc.encode)
		}
	case eInit_smartN:
		sc.smartN, _ = strconv.Atoi(content)
		log.Println("init smartN ", content)
	case eReverse:
		sc.reverseAddr = content
		if sc.smartN > 0 {
			go sc.checkSmart()
		}
		go sc.MultiListen()
	case eReady:
		atomic.AddInt32(&currReadyId, 1)
		sc.readyId = strconv.Itoa(int(currReadyId))
		log.Println("currid", sc.readyId, sc.id)
		common.WriteCrypt(pipe, -1, eReadyback, []byte(sc.readyId), sc.encode)
	case eReadyback:
		go func() {
			sc.pipesLock.RLock()
			pipes := sc.pipes
			for i, pipeInfo := range pipes {
				if i != readyIndex {
					common.WriteCrypt(pipeInfo.conn, -1, eCollect, []byte(content), sc.encode)
				} else {
					if *bReverse {
						common.WriteCrypt(pipeInfo.conn, -1, eReverse, []byte(*localAddr), sc.encode)
					} else {
						if !sc.bSmart {
							go sc.MultiListen()
						}
					}
				}
			}
			sc.pipesLock.RUnlock()
		}()
	case eCollect:
		readyId := content
		g_ClientMapLock.RLock()
		for _, c := range g_ClientMap {
			if c.readyId == readyId {
				log.Println("collect", sc.id, "=>", c.id, readyId)
				if c == sc {
					log.Println("collect", sc.id, "pipe already", readyId)
					g_ClientMapLock.RUnlock()
					return
				}
				maxId := 0

				f := func(c *Client, i int) {
					now := timeNow.now().Unix()
					c.pipes[i] = &pipeInfo{conn: pipe, total: 0, t: now, owner: nil, newindex: 0}
					sc.pipesLock.RLock()
					old := 0
					for _i, _info := range sc.pipes {
						if _info.conn == pipe {
							_info.Lock()
							_info.newindex = i
							old = _i
							_info.owner = c
							_info.Unlock()
							break
						}
					}
					sc.pipesLock.RUnlock()
					log.Println("collect", sc.id, "pipe", old, "=>", c.id, "pipe", i)
				}
				c.pipesLock.Lock()
				for i, _ := range c.pipes {
					if maxId < i {
						maxId = i
					}
				}
				f(c, maxId+1)
				c.pipesLock.Unlock()
				break
			}
		}
		g_ClientMapLock.RUnlock()
	case eInit_enc:
		tail := common.Xor(content)
		log.Println("got encrpyt key", tail)
		aesKey := "asd4" + tail
		aesBlock, _ := aes.NewCipher([]byte(aesKey))
		sc.SetCrypt(getEncodeFunc(aesBlock), getDecodeFunc(aesBlock))
	case eTunnel_msg_c_udp_sock:
		if session == nil {
			return
		}
		if session.localUdpConn == nil {
			return
		}
		buf := []byte(content)
		_, atyp := buf[2], buf[3]

		buf = buf[4:]
		size := len(buf)
		var host string
		var dst_addr []byte
		switch atyp {
		case 1: //ip v4
			dst_addr = make([]byte, 4)
			copy(dst_addr[:4], buf[:4])
			buf = buf[4:]
			size -= 4
		case 3:
			l := int(buf[0])
			dst_addr = buf[1 : l+1]
			buf = buf[l+1:]
			size -= l + 1
		}
		dst_port := make([]byte, 2)
		copy(dst_port[:], buf[:2])
		dst_port2 := (uint16(dst_port[0]) << 8) + uint16(dst_port[1])
		size -= 2
		switch atyp {
		case 1:
			host = fmt.Sprintf("%d.%d.%d.%d", dst_addr[0], dst_addr[1], dst_addr[2], dst_addr[3])
		case 3:
			host = string(dst_addr)
		}

		//log.Println("...", sessionId, len(host), string(host), atyp, dst_port2)
		var _addr *net.UDPAddr
		f := func(data []byte) {
			session.udpConnLock.RLock()
			if session.localUdpConn == nil {
				return
			}
			session.localUdpConn.WriteTo(data, _addr)
			//log.Println("write remote sock udp", sessionId, _addr.String(), len(data))
			session.udpConnLock.RUnlock()
		}
		data := buf[2:]
		if *dnsCacheNum > 0 && atyp == 3 {
			_data := make([]byte, len(data))
			copy(_data, data)
			go func() {
				_addr = &net.UDPAddr{}
				resChan := make(chan *dnsQueryRes)
				checkDns <- &dnsQueryReq{c: resChan, host: host}
				res := <-resChan
				_addr.IP = res.ip
				_addr.Port = int(dst_port2)
				f(_data)
			}()
		} else {
			url := net.JoinHostPort(host, fmt.Sprintf("%d", dst_port2))
			_addr, _ = net.ResolveUDPAddr("", url)
			f(data)
		}
	case eTunnel_msg_c_udp:
		if session != nil {
			if session.localUdpConn != nil {
				//log.Println("tunnel", (content), sessionId)
				if sc.stimeout > 0 {
					session.dieT = timeNow.now().Add(time.Duration(sc.stimeout) * time.Second)
				}
				pinfo.Add(int64(len(content)), timeNow.now().Unix())
				//log.Println("write conn data", len(content), sessionId)
				session.localUdpConn.WriteToUDP([]byte(content), session.localUdpAddr)
			} else {
				if session.udpCacheMsg == nil {
					session.udpCacheMsg = []string{}
				}
				session.udpCacheMsg = append(session.udpCacheMsg, content)
			}
		}
	case eTunnel_msg_c:
		if conn != nil {
			//log.Println("tunnel", (content), sessionId)
			if sc.stimeout > 0 {
				session.dieT = timeNow.now().Add(time.Duration(sc.stimeout) * time.Second)
			}
			pinfo.Add(int64(len(content)), timeNow.now().Unix())
			conn.Write([]byte(content))
		} else {
			if session != nil {
				session.cacheLock.Lock()
				session.cacheMsg += content
				session.cacheLock.Unlock()
			}
		}
	case eTunnel_close:
		go sc.removeSession(sessionId)
	case eTunnel_open:
		if sc.action != "socks5" {
			remote := sc.action
			if sc.bUdp {
				session := &clientSession{pipe: pinfo, localUdpConn: nil, dieT: timeNow.now().Add(time.Duration(sc.stimeout) * time.Second), localUdpAddr: nil, tunnelN: 1}
				sc.createSession(sessionId, session)
				go func() {
					sock, _err := net.ListenUDP("udp", &net.UDPAddr{})
					if _err != nil {
						log.Println("dial addr fail", _err.Error())
						msg := _err.Error()
						go common.WriteCrypt(pipe, sessionId, eTunnel_error, []byte(msg), sc.encode)
						sc.removeSession(sessionId)
						return
					}
					udpAddr, err := net.ResolveUDPAddr("udp", sc.action)
					if err != nil {
						log.Println("resolve addr fail", err.Error())
						msg := err.Error()
						go common.WriteCrypt(pipe, sessionId, eTunnel_error, []byte(msg), sc.encode)
						sock.Close()
						sc.removeSession(sessionId)
						return
					}
					session.localUdpAddr = udpAddr
					if sc.setSessionUdpConn(sessionId, sock) == nil {
						sock.Close()
						return
					}
					if session.udpCacheMsg != nil {
						for _, c := range session.udpCacheMsg {
							sock.WriteToUDP([]byte(c), session.localUdpAddr)
						}
					}
					go func() {
						arr := make([]byte, WriteBufferSize)
						for {
							n, _, err := sock.ReadFromUDP(arr)
							if err != nil {
								break
							} else {
								if common.WriteCrypt(pinfo.conn, sessionId, eTunnel_msg_s, arr[:n], sc.encode) != nil {
									break
								} else {
									session.pipe.Add(int64(n), timeNow.now().Unix())
								}
							}
						}
					}()
				}()
				return
			}
			session := &clientSession{pipe: pinfo, dieT: timeNow.now().Add(time.Duration(sc.stimeout) * time.Second), tunnelN: 1}
			if sc.action == "route" {
				remote = content
			}
			sc.createSession(sessionId, session)
			go func() {
				s_conn, err := net.DialTimeout("tcp", remote, 10*time.Second)
				if err != nil {
					log.Println("connect to local server fail:", err.Error(), remote)
					msg := "cannot connect to bind addr" + remote
					go common.WriteCrypt(pipe, sessionId, eTunnel_error, []byte(msg), sc.encode)
					sc.removeSession(sessionId)
					return
				} else {
					if sc.setSessionConn(sessionId, s_conn) == nil {
						s_conn.Close()
						return
					}
					session.cacheLock.Lock()
					if session.cacheMsg != "" {
						if session.localConn != nil {
							session.localConn.Write([]byte(session.cacheMsg))
						}
						session.cacheMsg = ""
					}
					session.cacheLock.Unlock()
					go session.handleLocalPortResponse(sc, sessionId, "")
				}
			}()
		} else {
			session = &clientSession{pipe: pinfo, localConn: nil, status: "init", recvMsg: "", dieT: timeNow.now().Add(time.Duration(sc.stimeout) * time.Second), tunnelN: 1}
			sc.createSession(sessionId, session)
			var hello reqMsg
			bOk, _ := hello.read([]byte(content))
			if !bOk {
				msg := "hello read err"
				go common.WriteCrypt(pipe, sessionId, eTunnel_error, []byte(msg), sc.encode)
				sc.removeSession(sessionId)
				return
			}
			if hello.cmd == 3 {
				//log.Println("listen session", sessionId)
				sock, _err := net.ListenUDP("udp", &net.UDPAddr{})
				if _err != nil {
					log.Println("cannot listenerUdp2 addr", _err.Error())
					go common.WriteCrypt(pipe, sessionId, eTunnel_error, []byte("cannot listenudp addr"), sc.encode)
					sc.removeSession(sessionId)
					return
				}
				if sc.setSessionUdpConn(sessionId, sock) == nil {
					go common.WriteCrypt(pipe, sessionId, eTunnel_error, []byte("session closed"), sc.encode)
					sc.removeSession(sessionId)
					sock.Close()
					return
				}
				//log.Println("fetch udp head")
				go func() {
					arr := make([]byte, WriteBufferSize+10)
					arr[0], arr[1], arr[2] = 0, 0, 0
					arr[3] = 1 //atyp, 1-7 ip,port
					for {
						n, addr, err := sock.ReadFromUDP(arr[10:])
						if err != nil {
							//log.Println("server udp read from err", n, err, sessionId)
							break
						} else {
							copy(arr[4:], addr.IP[len(addr.IP)-4:len(addr.IP)])
							arr[8] = byte((addr.Port >> 8) & 0xff)
							arr[9] = byte(addr.Port & 0xff)
							//log.Println("server udp read from", n, err, sessionId, addr.String(), []byte(addr.IP), arr[4:8])
							if common.WriteCrypt(pipe, sessionId, eTunnel_msg_s_udp_sock, arr[:n+10], sc.encode) != nil {
								break
							}
						}
					}
					sc.removeSession(sessionId)
					common.WriteCrypt(pipe, sessionId, eTunnel_close_s, []byte{}, sc.encode)
				}()
				return
			}
			go func() {
				var ansmsg ansMsg
				url := hello.url
				var s_conn net.Conn
				var err error
				if *dnsCacheNum > 0 && hello.atyp == 3 {
					host := string(hello.dst_addr[1 : 1+hello.dst_addr[0]])
					resChan := make(chan *dnsQueryRes)
					checkDns <- &dnsQueryReq{c: resChan, host: host}
					res := <-resChan
					err = res.err
					url = net.JoinHostPort(res.ip.String(), fmt.Sprintf("%d", hello.dst_port2))
				}
				if err == nil {
					//log.Println("try dial", url, sessionId)
					s_conn, err = DialTimeoutBind(hello.reqtype, url, 30*time.Second, socks5BindIP)
					//log.Println("try dial", url, "ok", sessionId)
				}
				if err != nil {
					log.Println("connect to local server fail:", err.Error(), url)
					ansmsg.gen(&hello, 4, "")
					go common.WriteCrypt(pipe, sessionId, eTunnel_msg_s_head, ansmsg.buf[:ansmsg.mlen], sc.encode)
					sc.removeSession(sessionId)
				} else {
					if sc.setSessionConn(sessionId, s_conn) == nil {
						s_conn.Close()
						return
					}
					session.cacheLock.Lock()
					if session.cacheMsg != "" {
						if session.localConn != nil {
							session.localConn.Write([]byte(session.cacheMsg))
						}
						session.cacheMsg = ""
					}
					session.cacheLock.Unlock()

					go session.handleLocalPortResponse(sc, sessionId, hello.url)
					ansmsg.gen(&hello, 0, *localAddr)
					go common.WriteCrypt(pipe, sessionId, eTunnel_msg_s_head, ansmsg.buf[:ansmsg.mlen], sc.encode)
					pinfo.Add(int64(ansmsg.mlen), timeNow.now().Unix())
				}
			}()
		}
	}
}

func (sc *Client) SetCrypt(encode, decode func([]byte) []byte) {
	sc.encode = encode
	sc.decode = decode
}

func (sc *Client) sessionCheckDie() {
	t := time.NewTicker(time.Second)
out:
	for {
		select {
		case <-t.C:
			now := timeNow.now()
			for id, session := range sc.sessions {
				if now.After(session.dieT) {
					session.connLock.RLock()
					if session.localConn != nil {
						log.Println("try close timeout session connection", session.localConn.RemoteAddr(), id)
						session.localConn.Close()
					}
					session.connLock.RUnlock()
					if session.localUdpAddr != nil {
						log.Println("try close timeout udp session connection", session.localUdpAddr.String(), id)
						//delete(sc.sessions, id)
						common.WriteCrypt(session.pipe.conn, id, eTunnel_close, []byte{}, sc.encode)
						sc.removeSession(id)
					}
				}
			}
		case <-sc.quit:
			break out
		}
	}
	t.Stop()
}

func (sc *Client) Quit() {
	sc._Quit()
	sc.pipesLock.Lock()
	defer sc.pipesLock.Unlock()
	for id, pipeInfo := range sc.pipes {
		pipeInfo.conn.Close()
		delete(sc.pipes, id)
	}
	if sc.listener != nil {
		sc.listener.Close()
	}
	if sc.listenerUdp != nil {
		sc.listenerUdp.Close()
	}
	//de.FreeOSMemory()
}

func (sc *Client) _Quit() {
	sc.closeLock.Lock()
	if sc.closed == 1 {
		sc.closeLock.Unlock()
		return
	}
	sc.closed = 1
	sc.closeLock.Unlock()
	close(sc.quit)
	sc.sessionLock.RLock()
	for _, session := range sc.sessions {
		session.connLock.RLock()
		if session.localConn != nil {
			session.localConn.Close()
		}
		session.connLock.RUnlock()
		session.udpConnLock.RLock()
		if session.localUdpConn != nil {
			session.localUdpConn.Close()
		}
		session.udpConnLock.RUnlock()
	}
	sc.sessionLock.RUnlock()
	log.Println("client quit", sc.id, len(sc.sessions))
	g_ClientMapLock.Lock()
	delete(g_ClientMap, sc.id)
	g_ClientMapLock.Unlock()
	//de.FreeOSMemory()
}

///////////////////////multi pipe support
var g_LocalConn net.Listener
var g_LocalConnLock sync.RWMutex

func (sc *Client) MultiListen() bool {
	if sc.bUdp {
		if sc.listenerUdp == nil {
			udpAddr, err := net.ResolveUDPAddr("udp", sc.reverseAddr)
			if err != nil {
				log.Println("cannot listenerUdp addr", err.Error())
				return false
			}
			sock, _err := net.ListenUDP("udp", udpAddr)
			if _err != nil {
				log.Println("cannot listenerUdp2 addr", _err.Error())
				return false
			}

			genId := func(addr []byte) int {
				n := 0
				for i, v := range addr {
					n += int(v) * i
				}
				return n
			}
			sc.listenerUdp = sock
			println("udp client service start success,please connect", sc.reverseAddr)
			var tmp = make([]byte, WriteBufferSize)
			for {
				n, from, err := sock.ReadFromUDP(tmp)
				if err != nil {
					e, ok := err.(net.Error)
					if !ok || !e.Timeout() {
						//log.Println("udp client over", e.Error())
						break
					}
				}
				pipe := sc.getOnePipe()
				if pipe == nil {
					log.Println("cannot get pipe for client, wait for recover...")
					time.Sleep(time.Second)
					continue
				}
				hashStr := from.String()
				sessionId := genId([]byte(hashStr))
				session := sc.getSession(sessionId)
				if session == nil || session.hash != hashStr {
					session = &clientSession{pipe: pipe, localUdpAddr: from, dieT: timeNow.now().Add(time.Duration(sc.stimeout) * time.Second), hash: hashStr, tunnelN: 1}
					sc.createSession(sessionId, session)
					log.Println("create udp session", sessionId)
					common.WriteCrypt(pipe.conn, sessionId, eTunnel_open, tmp[:n], sc.encode)
				}
				if common.WriteCrypt(pipe.conn, sessionId, eTunnel_msg_c_udp, tmp[:n], sc.encode) != nil {
					break
				} else {
					if sc.stimeout > 0 {
						session.dieT = timeNow.now().Add(time.Duration(sc.stimeout) * time.Second)
					}
				}
			}
			sc.listenerUdp = nil
		}
		return true
	}
	if sc.listener == nil {
		var err error
		sc.listener, err = net.Listen("tcp", sc.reverseAddr)
		if err != nil {
			log.Println("cannot listen addr:" + err.Error())
			sc.pipesLock.RLock()
			for _, pipeInfo := range sc.pipes {
				common.WriteCrypt(pipeInfo.conn, -1, eShowandquit, []byte("cannot listen addr:"+err.Error()), sc.encode)
			}
			sc.pipesLock.RUnlock()
			return false
		}

		println("client service start success,please connect", sc.reverseAddr)
		func() {
			for {
				conn, err := sc.listener.Accept()
				if err != nil {
					break
				}
				pipe := sc.getOnePipe()
				if pipe == nil && !sc.bSmart {
					log.Println("cannot get pipe for client, wait for recover...")
					time.Sleep(time.Second)
					continue
				}
				session := &clientSession{pipe: pipe, localConn: conn, status: "init", dieT: timeNow.now().Add(time.Duration(sc.stimeout) * time.Second), tunnelN: 1}
				sessionId := sc.createSession(-1, session)
				go session.handleLocalServerResponse(sc, sessionId)
			}
			sc.listener = nil
			sc.pipesLock.RLock()
			for _, pipeInfo := range sc.pipes {
				common.WriteCrypt(pipeInfo.conn, -1, eShowandquit, []byte("server listener quit"), sc.encode)
			}
			sc.pipesLock.RUnlock()
		}()
	}
	return true
}

func (sc *Client) getOnePipe() *pipeInfo {
	sc.pipesLock.RLock()
	defer sc.pipesLock.RUnlock()
	size := len(sc.pipes)
	if size == 1 {
		pipeInfo, b := sc.pipes[0]
		if b {
			return pipeInfo
		}
	}
	//tmp := []int{}
	var choose *pipeInfo
	var min float64 = -1
	now := timeNow.now().Unix()
	for _, info := range sc.pipes {
		info.RLock()
		dt := now - info.t
		if dt <= 0 {
			dt = 1
		}
		if dt > 60 {
			info.RUnlock()
			return info //transer data for over 60s
		}
		rate := float64(info.total) / float64(dt)
		if min == -1 {
			min = rate
			choose = info
		} else if rate < min {
			min = rate
			choose = info
		}
		info.RUnlock()
	}
	//log.Println("choose pipe for ", choose, "of", size, min)
	return choose
}

type decideStatus byte

const (
	NotDecide = decideStatus(iota)
	DecideLocal
	DecideRemote
)

type hostWay struct {
	decide      decideStatus
	times       int32
	host        string
	overt       time.Time
	decideTimes int32
	sync.RWMutex
}

func (h *hostWay) update() {
	if timeNow.now().After(h.overt) {
		h.Lock()
		atomic.StoreInt32(&h.times, 0)
		atomic.StoreInt32(&h.decideTimes, 0)
		h.decide = NotDecide
		h.Unlock()
	}
}

func (h *hostWay) getDecide() decideStatus {
	if timeNow.now().After(h.overt) {
		return NotDecide
	}
	h.RLock()
	defer h.RUnlock()
	return h.decide
}

func (h *hostWay) setDecide(s decideStatus) {
	h.Lock()
	h.decide = s
	h.overt = timeNow.now().Add(5 * time.Minute)
	h.Unlock()
}

type smartSession struct {
	way        *hostWay
	conn       net.Conn
	client     *Client
	id         int
	localconn  net.Conn
	cacheLock  sync.RWMutex
	cacheMsg   string
	status     int32
	statusLock sync.RWMutex
}

func (st *smartSession) onRecv(msg []byte) {
	if len(msg) <= 0 {
		return
	}
	st.cacheLock.Lock()
	if st.conn != nil {
		st.conn.Write(msg)
	} else {
		st.cacheMsg += string(msg)
	}
	st.cacheLock.Unlock()
}
func (st *smartSession) startRoute(remoteAddr string) {
	var s_conn net.Conn
	url := remoteAddr
	var err error
	s_conn, err = net.DialTimeout("tcp", url, 30*time.Second)
	var pipe *pipeInfo
	session := st.client.getSession(st.id)
	if session != nil {
		pipe = session.pipe
	}
	if err != nil {
		log.Println("smart connect to local server fail:", err.Error(), url)
		st.client.OnTunnelRecv(nil, st.id, eTunnel_error, err.Error(), nil)
	} else {
		st.statusLock.RLock()
		if st.status == 1 {
			s_conn.Close()
			st.statusLock.RUnlock()
			return
		}
		st.conn = s_conn
		st.statusLock.RUnlock()
		st.cacheLock.RLock()
		if st.cacheMsg != "" {
			s_conn.Write([]byte(st.cacheMsg))
		}
		st.cacheLock.RUnlock()
		go func() {
			reader := bufio.NewReader(s_conn)
			arr := make([]byte, WriteBufferSize)
			for {
				size, err := reader.Read(arr)
				if err != nil {
					break
				}
				//log.Println("recv", url, size, st.id, st.way.decide, st.way.times)
				st.client.OnTunnelRecv(nil, st.id, eTunnel_msg_s, string(arr[:size]), pipe)
			}
			st.client.OnTunnelRecv(nil, st.id, eTunnel_close_s, "", pipe)
			st.close()
		}()
	}
}

func (st *smartSession) close() {
	st.statusLock.Lock()
	if st.status == 1 {
		st.statusLock.Unlock()
		return
	}
	st.status = 1
	st.statusLock.Unlock()
	if st.conn != nil {
		st.conn.Close()
	}
}

func (st *smartSession) start(hello reqMsg) {
	var s_conn net.Conn
	url := hello.url
	var err error
	if *dnsCacheNum > 0 && hello.atyp == 3 {
		host := string(hello.dst_addr[1 : 1+hello.dst_addr[0]])
		resChan := make(chan *dnsQueryRes)
		checkDns <- &dnsQueryReq{c: resChan, host: host}
		res := <-resChan
		err = res.err
		url = net.JoinHostPort(res.ip.String(), fmt.Sprintf("%d", hello.dst_port2))
	}
	if err == nil {
		s_conn, err = net.DialTimeout(hello.reqtype, url, 30*time.Second)
	}
	var pipe *pipeInfo
	session := st.client.getSession(st.id)
	if session != nil {
		pipe = session.pipe
	}
	var ansmsg ansMsg
	if err != nil {
		log.Println("smart connect to local server fail:", err.Error(), url)

		ansmsg.gen(&hello, 4, "")
		st.client.OnTunnelRecv(nil, st.id, eTunnel_msg_s_head, string(ansmsg.buf[:ansmsg.mlen]), pipe)
	} else {
		st.statusLock.RLock()
		if st.status == 1 {
			s_conn.Close()
			st.statusLock.RUnlock()
			return
		}
		st.conn = s_conn
		st.statusLock.RUnlock()
		st.cacheLock.RLock()
		if st.cacheMsg != "" {
			s_conn.Write([]byte(st.cacheMsg))
		}
		st.cacheLock.RUnlock()
		ansmsg.gen(&hello, 0, *localAddr)
		st.client.OnTunnelRecv(nil, st.id, eTunnel_msg_s_head, string(ansmsg.buf[:ansmsg.mlen]), pipe)
		go func() {
			reader := bufio.NewReader(s_conn)
			arr := make([]byte, WriteBufferSize)
			for {
				size, err := reader.Read(arr)
				if err != nil {
					break
				}
				//log.Println("recv", url, size, st.id, st.way.decide, st.way.times)
				st.client.OnTunnelRecv(nil, st.id, eTunnel_msg_s, string(arr[:size]), pipe)
			}
			st.client.OnTunnelRecv(nil, st.id, eTunnel_close_s, "", pipe)
			st.close()
		}()
	}
}

func (session *clientSession) checkDecide(bLocal bool) *hostWay {
	_session := session.sm
	//log.Println("check decide", _session)
	var _way *hostWay
	if _session != nil {
		way := _session.way
		//log.Println("check decide2", way.host, way.getDecide(), bLocal)
		if way.getDecide() == NotDecide {
			if bLocal {
				way.setDecide(DecideRemote)
			} else {
				way.setDecide(DecideLocal)
			}
			_way = way
			log.Println("smart decide immediately", way.decide, way.host)
		}
	}
	return _way
}

func (session *clientSession) endSmartMonitor(sc *Client, sessionId int, bLocal bool) {
	_session := session.sm
	if _session != nil {
		way := _session.way
		if !bLocal {
			_session.close()
		} else {
			if session.pipe != nil {
				common.WriteCrypt(session.pipe.conn, sessionId, eTunnel_close, []byte{}, sc.encode)
			}
		}
		if way.getDecide() == NotDecide {
			//log.Println("endSmartMonitor", sessionId, bLocal, session.way.host, session.way.times)
			if bLocal {
				atomic.AddInt32(&way.times, 1)
			} else {
				atomic.AddInt32(&way.times, -1)
			}
			if int(atomic.AddInt32(&way.decideTimes, 1)) >= sc.smartN {
				if atomic.LoadInt32(&way.times) >= 0 {
					log.Println("smart decide local", way.host)
					way.setDecide(DecideLocal)
				} else {
					log.Println("smart decide remote", way.host)
					way.setDecide(DecideRemote)
				}
			}
		}
	}
}

func (sc *Client) getHostWay(host string) *hostWay {
	if !sc.bSmart {
		return nil
	}
	sc.hostWayLock.Lock()
	defer sc.hostWayLock.Unlock()
	way, b := sc.hostWayTbl[host]
	if b {
		way.update()
		return way
	}
	way = &hostWay{decide: NotDecide, host: host, overt: timeNow.now().Add(5 * time.Minute)}
	sc.hostWayTbl[host] = way
	return way
}

func (sc *Client) checkSmart() {
	t := time.NewTicker(time.Minute)
out:
	for {
		select {
		case <-t.C:
			now := timeNow.now()
			sc.hostWayLock.Lock()
			for host, way := range sc.hostWayTbl {
				if now.After(way.overt) {
					log.Println("smart remove decide", host)
					delete(sc.hostWayTbl, host)
				}
			}
			sc.hostWayLock.Unlock()
		case <-sc.quit:
			break out
		}
	}
	t.Stop()
}

///////////////////////multi pipe support
func (session *clientSession) addSmartMonitorRoute(sc *Client, sessionId int, remoteAddr string, way *hostWay, conn net.Conn) *smartSession {
	_session := &smartSession{way: way, client: sc, id: sessionId, localconn: conn}
	session.sm = _session
	go _session.startRoute(remoteAddr)
	return _session
}
func (session *clientSession) addSmartMonitor(sc *Client, sessionId int, hello reqMsg, way *hostWay, conn net.Conn) *smartSession {
	_session := &smartSession{way: way, client: sc, id: sessionId, localconn: conn}
	session.sm = _session
	go _session.start(hello)
	return _session
}

func (session *clientSession) handleLocalPortResponse(client *Client, id int, url string) {
	sessionId := id
	session.connLock.RLock()
	conn := session.localConn
	session.connLock.RUnlock()
	if conn == nil {
		return
	}
	arr := make([]byte, WriteBufferSize)
	reader := bufio.NewReader(conn)
	var pipe net.Conn
	if session.pipe != nil {
		pipe = session.pipe.conn
	}
	if pipe == nil {
		client.removeSession(sessionId)
		return
	}
	for {
		size, err := reader.Read(arr)
		if err != nil {
			break
		}
		if client.stimeout > 0 {
			session.dieT = timeNow.now().Add(time.Duration(client.stimeout) * time.Second)
		}
		if common.WriteCrypt(pipe, id, eTunnel_msg_s, arr[0:size], client.encode) != nil {
			break
		} else {
			session.pipe.Add(int64(size), timeNow.now().Unix())
		}
	}
	// log.Println("handlerlocal down")
	client.removeSession(sessionId)
	common.WriteCrypt(pipe, sessionId, eTunnel_close_s, []byte{}, client.encode)
}

func (session *clientSession) handleLocalServerResponse(client *Client, sessionId int) {
	buffSize := WriteBufferSize
	var pipe net.Conn
	if session.pipe != nil {
		pipe = session.pipe.conn
	}
	if pipe == nil {
		if !client.bSmart {
			client.removeSession(sessionId)
			return
		}
	}
	session.connLock.RLock()
	conn := session.localConn
	session.connLock.RUnlock()
	remote := ""
	var host string
	var smartSession *smartSession
	var way *hostWay
	var sessionDecide decideStatus

	if client.action == "route" {
		c := make(chan string)
		checkRealAddrChan <- &queryRealAddrInfo{conn, c}
		remote = <-c
		if remote == "" {
			client.removeSession(sessionId)
			return
		}
		host = remote
	}
	if client.action != "socks5" {
		if *bSrc {
			log.Println("map", conn.RemoteAddr().String(), client.action)
		}
		if client.bSmart {
			way = client.getHostWay(host)
			decide := way.getDecide()
			if decide != NotDecide || pipe == nil {
				session.decideLock.Lock()
				if pipe == nil {
					session.decide = DecideLocal
				} else {
					session.decide = decide
				}
				sessionDecide = session.decide
				session.decideLock.Unlock()
			}
			session.tunnelN = 0
			if pipe != nil {
				session.tunnelN++
			}
			if sessionDecide != DecideRemote {
				smartSession = session.addSmartMonitorRoute(client, sessionId, host, way, conn)
				session.tunnelN++
			}
			if sessionDecide != DecideLocal {
				common.WriteCrypt(pipe, sessionId, eTunnel_open, []byte(remote), client.encode)
			}
		} else {
			common.WriteCrypt(pipe, sessionId, eTunnel_open, []byte(remote), client.encode)
		}
	}
	arr := make([]byte, buffSize)
	reader := bufio.NewReader(conn)
	bParsed := false
	bNeedBreak := false
	var recv string

	for {
		size, err := reader.Read(arr)
		if err != nil {
			break
		}
		if client.stimeout > 0 {
			session.dieT = timeNow.now().Add(time.Duration(client.stimeout) * time.Second)
		}
		if client.action == "socks5" && !bParsed {
			session.processSockProxy(string(arr[0:size]), func(head []byte, _host string, hello reqMsg) {
				if hello.cmd == 3 {
					udpAddr, _ := net.ResolveUDPAddr("udp", client.reverseAddr)
					sock, _err := net.ListenUDP("udp", &net.UDPAddr{IP: udpAddr.IP})
					if _err != nil {
						log.Println("cannot listenerUdp2 addr", _err.Error())
						return
					}
					session.listenerUdp = sock
					session.realUdpAddr = sock.LocalAddr().(*net.UDPAddr)
					//log.Println("lissssss", session.realUdpAddr, sessionId)
					go func() {
						var tmp = make([]byte, WriteBufferSize)
						for {
							n, addr, err := sock.ReadFromUDP(tmp)
							//log.Println("parse head", frag, atyp, url, dst_port2, size, addr)
							if err != nil {
								e, ok := err.(net.Error)
								if !ok || !e.Timeout() {
									//log.Println("udp client over", e.Error())
									break
								}
							}
							session := client.getSession(sessionId)
							if session == nil {
								log.Println("no session, drop data for", addr, sessionId)
								break
							}

							buf := tmp
							//log.Println("read from socks5", n, addr, sessionId)
							//println("test", msg.ver, msg.cmd, msg.rsv, msg.atyp)

							buf = buf[4:]

							session.responseUdpAddr = addr
							pipe := client.getOnePipe()
							if pipe == nil {
								log.Println("cannot get pipe for client, wait for recover...")
								time.Sleep(time.Second)
								continue
							}
							//log.Println("wwwww",sessionId, n, len(tmp))
							if common.WriteCrypt(pipe.conn, sessionId, eTunnel_msg_c_udp_sock, tmp[:n], client.encode) != nil {
								break
							}
						}
						sock.Close()
						session.listenerUdp = nil
						client.removeSession(sessionId)
					}()
					var ansmsg ansMsg
					ansmsg.gen(&hello, 0, session.realUdpAddr.String())
					session.localConn.Write(ansmsg.buf[:ansmsg.mlen])
					srcAddr := hello.url
					session.udpAddr = srcAddr
					bParsed = true
					common.WriteCrypt(pipe, sessionId, eTunnel_open, head, client.encode)
					return
				}
				host = _host
				way = client.getHostWay(host)
				if *bSrc {
					log.Println("map", conn.RemoteAddr().String(), host)
				}
				if way != nil {
					decide := way.getDecide()
					if decide != NotDecide || pipe == nil {
						session.decideLock.Lock()
						if pipe == nil {
							session.decide = DecideLocal
						} else {
							session.decide = decide
						}
						sessionDecide = session.decide
						session.decideLock.Unlock()
					}
				}
				//log.Println("begin socks5", sessionId, sessionDecide, host, way)
				session.tunnelN = 0
				if pipe != nil {
					session.tunnelN++
				}
				if way != nil && sessionDecide != DecideRemote {
					smartSession = session.addSmartMonitor(client, sessionId, hello, way, conn)
					session.tunnelN++
				}
				if way == nil || sessionDecide != DecideLocal {
					common.WriteCrypt(pipe, sessionId, eTunnel_open, head, client.encode)
					if common.WriteCrypt(pipe, sessionId, eTunnel_msg_c, []byte(session.recvMsg), client.encode) != nil {
						bNeedBreak = true
					} else {
						session.pipe.Add(int64(len(session.recvMsg)), timeNow.now().Unix())
						if *bCache {
							recv += session.recvMsg
						}
						if smartSession != nil {
							smartSession.onRecv([]byte(session.recvMsg))
						}
					}
				} else {
					if session.pipe != nil {
						session.pipe.Add(int64(len(session.recvMsg)), timeNow.now().Unix())
					}
					if *bCache {
						recv += session.recvMsg
					}
					if smartSession != nil {
						smartSession.onRecv([]byte(session.recvMsg))
					}
				}
				bParsed = true
			})
		} else {
			if smartSession != nil {
				smartSession.onRecv(arr[:size])
			}
			session.decideLock.RLock()
			sessionDecide = session.decide
			session.decideLock.RUnlock()
			if way == nil || sessionDecide != DecideLocal {
				if common.WriteCrypt(pipe, sessionId, eTunnel_msg_c, arr[0:size], client.encode) != nil {
					bNeedBreak = true
				} else {
					session.pipe.Add(int64(size), timeNow.now().Unix())
					if *bCache && client.action == "socks5" {
						recv += string(arr[:size])
					}
				}
			} else {
				if session.pipe != nil {
					session.pipe.Add(int64(size), timeNow.now().Unix())
				}
				if *bCache && client.action == "socks5" {
					recv += string(arr[:size])
				}
			}
		}
		if bNeedBreak {
			break
		}
	}
	if pipe != nil {
		common.WriteCrypt(pipe, sessionId, eTunnel_close, []byte{}, client.encode)
	}
	client.removeSession(sessionId)
	if smartSession != nil {
		smartSession.close()
	}
	if *bCache && client.action == "socks5" {
		arr := strings.Split(recv, "\r\n\r\n")
		for _, s := range arr {
			if s != "" {
				_url := s + "\r\n\r\n"
				go func() { cacheChan <- reqArg{_url, host, 0} }()
			}
		}
	}
}

func handleUrl() {
	for {
		select {
		case arg := <-cacheChan:
			url, host := arg.url, arg.host
			reader := bufio.NewReader(strings.NewReader(url))
			req, er := http.ReadRequest(reader)
			if er == nil {
				if req.Method == "GET" {
					req.URL.Scheme = "http"
					req.URL.Host = host
					req.RequestURI = ""
					req.Header.Del("If-Modified-Since")
					req.Header.Del("If-None-Match")
					req.Header.Set("Accept-Encoding", "")
					client := &http.Client{}
					res, _er := client.Do(req)
					if _er == nil {
						defer res.Body.Close()
						b, _ := ioutil.ReadAll(res.Body)
						if len(b) == 0 && arg.times < 3 {
							//log.Println("retry", arg.times, res.Status)
							go func() {
								arg.times += 1
								cacheChan <- arg
							}()
							break
						}
						_host, _, _ := net.SplitHostPort(host)
						file := filepath.Join("./cache/", _host, req.URL.Path)
						if filepath.Ext(file) == "" || filepath.Dir(file) == filepath.Dir("./cache/") {
							file = filepath.Join("./cache/", _host, req.URL.Path, "index.html")
						}
						log.Println("url", filepath.Dir(file), file)
						os.MkdirAll(filepath.Dir(file), 0777)
						ioutil.WriteFile(file, b, 0777)
					} else {
						log.Println("get error", _er.Error(), arg.times)
						if arg.times < 3 {
							go func() {
								arg.times += 1
								cacheChan <- arg
							}()
							break
						}
					}

				}
			} else {
			}
		}
	}
}
