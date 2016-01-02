package main

import (
	"./common"
	"./pipe"
	"./platform"
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	_ "crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"os/user"
	"path"
	"runtime"
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
)

//var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
const WriteBufferSize = pipe.WriteBufferSize

var authKey = flag.String("auth", "", "key for auth")
var pipeN = flag.Int("pipe", 1, "pipe num(todo...)")
var threadN = flag.Int("thread", 1, "replace of GOMAXPROCS")
var bTcp = flag.Bool("tcp", false, "use tcp to replace udp")
var xorData = flag.String("xor", "", "xor key,c/s must use a some key")

var serviceAddr = flag.String("service", "", "listen addr for client connect")
var localAddr = flag.String("local", "", "if local not empty, treat me as client, this is the addr for local listen, otherwise, treat as server,use \"udp:\" ahead, open udp port")
var remoteAction = flag.String("action", "socks5", "for client control server, if action is socks5,remote is socks5 server, if is addr like 127.0.0.1:22, remote server is a port redirect server, can use \"udp:\" ahead,\"route\" is for transparent socks")
var bVerbose = flag.Bool("v", false, "verbose mode")
var bShowVersion = flag.Bool("version", false, "show version")
var bEncrypt = flag.Bool("encrypt", false, "p2p mode encrypt")
var dnsCacheNum = flag.Int("dnscache", 0, "if > 0, dns will cache xx minutes")
var timeOut = flag.Int("timeout", 100, "udp pipe set timeout(seconds)")

var bListenUdp = flag.Bool("listenudp", false, "listen udp mode")
var bDebug = flag.Int("debug", 0, "more output log")
var bReverse = flag.Bool("r", false, "reverse mode, if true, client 's \"-local\" address will be listened on server side")
var sessionTimeout = flag.Int("session_timeout", 0, "if > 0, session will check itself if it's alive, if no msg tranfer for some seconds, socket will be closed, use this to avoid of zombie tcp sockets")
var bCache = flag.Bool("cache", false, "(valid in socks5 mode)if cache is true,save files requested with GET method into cache/ dir,cache request not pass through server side,no support for https")

var clientType = 1
var currReadyId = 0

type reqArg struct {
	url   string
	host  string
	times int
}

var cacheChan chan reqArg

const maxPipes = 100

var pipen int32 = 0

func clientReport(r int) {
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
				client.Quit()
			}
		}
	}
}

type _time struct {
	time.Time
	sync.RWMutex
}

var timeNow _time

type dnsInfo struct {
	Ip                  string
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
	timeNow.RLock()
	defer timeNow.RUnlock()
	return timeNow.Unix() < u.overTime
}

func (u *dnsInfo) SetCacheTime(t int64) {
	if t >= 0 {
		u.cacheTime = t
	} else {
		t = u.cacheTime
	}
	timeNow.RLock()
	defer timeNow.RUnlock()
	u.overTime = t + timeNow.Unix()
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

func checkUdp(s string) (string, bool) {
	action := s
	bUdp := false
	if strings.HasPrefix(s, "udp:") {
		action = strings.TrimPrefix(action, "udp:")
		bUdp = true
	}
	return action, bUdp
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

func CreateSessionAndLoop(bIsTcp bool, idindex int) {
	CreateSession(bIsTcp, idindex)
	time.AfterFunc(time.Second*3, func() {
		CreateSessionAndLoop(bIsTcp, idindex)
	})
	log.Println("sys will reconnect pipe", idindex, "after 3 seconds")
}

func CreateSession(bIsTcp bool, idindex int) bool {
	var s_conn net.Conn
	var err error
	if bIsTcp {
		s_conn, err = net.DialTimeout("tcp", *serviceAddr, 30*time.Second)
	} else {
		s_conn, err = pipe.DialTimeout(*serviceAddr, *timeOut)
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
		client = &Client{id: id, ready: true, bUdp: false, sessions: make(map[int]*clientSession), pipes: make(map[int]*pipeInfo), quit: make(chan bool)}
		g_ClientMapLock.Lock()
		g_ClientMap[id] = client
		g_ClientMapLock.Unlock()
		if *sessionTimeout > 0 {
			go client.sessionCheckDie()
		}
	}
	if *authKey != "" {
		log.Println("request auth key", *authKey)
		common.Write(s_conn, -1, eAuth, []byte(common.Xor(*authKey)))
	}
	if *bEncrypt {
		log.Println("request encrypt")
		encrypt_tail := client.encryptstr
		if encrypt_tail == "" {
			timeNow.RLock()
			encrypt_tail = string([]byte(fmt.Sprintf("%d%d", int32(timeNow.Unix()), (rand.Intn(100000) + 100)))[:12])
			timeNow.RUnlock()
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
	client.reverseAddr = *localAddr
	client.action, client.bUdp = checkUdp(*remoteAction)
	common.WriteCrypt(s_conn, -1, eInit_action, []byte(*remoteAction), client.encode)
	client.stimeout = *sessionTimeout

	timeNow.RLock()
	pinfo := &pipeInfo{conn: s_conn, total: 0, t: timeNow.Unix(), owner: nil, newindex: 0}
	timeNow.RUnlock()
	client.pipesLock.Lock()
	client.pipes[idindex] = pinfo
	client.pipesLock.Unlock()
	clientReport(idindex)
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
	clientReport(-1)
	client.pipesLock.Lock()
	delete(client.pipes, idindex)
	client.pipesLock.Unlock()
	s_conn.Close()

	client.pipesLock.RLock()
	l := len(client.pipes)
	client.pipesLock.RUnlock()
	if l == 0 {
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
		g_LocalConn, err = pipe.Listen(addr)
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
		g_ClientMapLock.RLock()
		client, have := g_ClientMap[id]
		g_ClientMapLock.RUnlock()
		if !have {
			client = &Client{id: id, ready: true, bUdp: false, sessions: make(map[int]*clientSession), pipes: make(map[int]*pipeInfo), quit: make(chan bool)}
			g_ClientMapLock.Lock()
			g_ClientMap[id] = client
			g_ClientMapLock.Unlock()
			if *authKey == "" {
				client.authed = true
			}
		}

		idindex := -1
		for i := 0; i < maxPipes; i++ {
			client.pipesLock.RLock()
			_, bHave := client.pipes[i]
			client.pipesLock.RUnlock()
			if !bHave {
				idindex = i
				timeNow.RLock()
				now := timeNow.Unix()
				timeNow.RUnlock()
				client.pipesLock.Lock()
				client.pipes[i] = &pipeInfo{conn: conn, total: 0, t: now, owner: nil, newindex: 0}
				client.pipesLock.Unlock()
				break
			}
		}
		if idindex == -1 {
			log.Println("cannot over max pipes", maxPipes, "for", id)
		} else {
			log.Println("add pipe", idindex, "for", id)
		}
		go client.ServerProcess(bIsTcp, idindex)
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
	c       chan *dnsQueryRes
	host    string
	port    int
	reqtype string
	url     string
}

type dnsQueryBack struct {
	host   string
	status string
	conn   net.Conn
	err    error
}

type dnsQueryRes struct {
	conn net.Conn
	err  error
	ip   string
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
	for {
		select {
		case info := <-checkDns:
			cache := common.GetCacheContainer("dns")
			cacheInfo := cache.GetCache(info.host)
			if cacheInfo == nil {
				cache.AddCache(info.host, &dnsInfo{Queue: []*dnsQueryReq{info}, Status: "querying"}, int64(*dnsCacheNum*60))
				go func() {
					back := &dnsQueryBack{host: info.host}
					//log.Println("try dial", info.url)
					s_conn, err := net.DialTimeout(info.reqtype, info.url, 30*time.Second)
					//log.Println("try dial", info.url, "ok")
					if err != nil {
						back.status = "queryfail"
						back.err = err
					} else {
						back.status = "queryok"
						back.conn = s_conn
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
					_cacheInfo.Ip, _, _ = net.SplitHostPort(info.conn.RemoteAddr().String())
					_cacheInfo.SetCacheTime(-1)
					debug("process the queue of host", info.host, len(_cacheInfo.Queue))
					conn := info.conn
					for _, _info := range _cacheInfo.Queue {
						c := _info.c
						go func() {
							c <- &dnsQueryRes{ip: _cacheInfo.Ip, conn: conn}
						}()
						conn = nil
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
	runtime.GOMAXPROCS(*threadN)
	flag.Parse()
	/*if *cpuprofile != "" {
		f, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}*/
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
	go checkRealAddr()
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
	_, bUdp := checkUdp(*remoteAction)
	if bUdp && *sessionTimeout == 0 {
		println("you must assign session_timeout arg")
		return
	}
	if clientType == 1 && *pipeN > maxPipes {
		println("pipe need <=", maxPipes)
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
	g_ClientMapLock.Lock()
	g_ClientMap = make(map[string]*Client)
	g_ClientMapLock.Unlock()
	if *bDebug > 0 {
		go func() {
			c := time.NewTicker(time.Second * 15)
			for _ = range c.C {
				log.Println("begin =====")
				timeNow.RLock()
				now := timeNow.Unix()
				timeNow.RUnlock()
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
			g_ClientMapLock.RLock()
			_map := g_ClientMap
			g_ClientMapLock.RUnlock()
			for _, client := range _map {
				client.Quit()
				atomic.StoreInt32(&pipen, 0)
			}
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
			for i := 0; i < *pipeN; i++ {
				go CreateSessionAndLoop(*bTcp, i)
			}
			w.Done()
		}
	}
	loop()
	w.Wait()
	log.Println("service shutdown")
}

type clientSession struct {
	pipe         *pipeInfo
	localConn    net.Conn
	localUdpConn *net.UDPConn
	localUdpAddr *net.UDPAddr
	connLock     sync.RWMutex
	status       string
	recvMsg      string
	extra        uint8
	dieT         time.Time
}

func (session *clientSession) processSockProxy(sessionId int, content string, callback func([]byte, string)) {
	session.recvMsg += content
	bytes := []byte(session.recvMsg)
	size := len(bytes)
	//log.Println("recv msg-====", len(session.recvMsg),  session.status, sessionId)
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
		go func() {
			session.connLock.RLock()
			session.localConn.Write(send)
			session.connLock.RUnlock()
		}()
		session.status = "hello"
		session.recvMsg = string(bytes[session.extra:])
		session.extra = 0
	case "hello":
		var hello reqMsg
		bOk, tail := hello.read(bytes)
		if bOk {
			session.status = "ok"
			session.recvMsg = string(tail)
			callback(bytes, hello.url)
		}
		return
	case "ok":
		return
	}
	session.processSockProxy(sessionId, "", callback)
}

type ansMsg struct {
	ver  uint8
	rep  uint8
	rsv  uint8
	atyp uint8
	buf  [300]uint8
	mlen uint16
}

func (msg *ansMsg) gen(req *reqMsg, rep uint8) {
	msg.ver = 5
	msg.rep = rep //rfc1928
	msg.rsv = 0
	msg.atyp = 1 //req.atyp

	msg.buf[0], msg.buf[1], msg.buf[2], msg.buf[3] = msg.ver, msg.rep, msg.rsv, msg.atyp
	for i := 5; i < 11; i++ {
		msg.buf[i] = 0
	}
	msg.mlen = 10
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
	ready          bool
	bUdp           bool
	action         string
	closed         bool
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
	quit           chan bool
}

// pipe : client to client
// local : client to local apps
func (sc *Client) getSession(sessionId int) *clientSession {
	if sessionId < 0 {
		return nil
	}
	sc.sessionLock.RLock()
	defer sc.sessionLock.RUnlock()
	session, bHave := sc.sessions[sessionId]
	if bHave {
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
	if bHave {
		delete(sc.sessions, sessionId)
		session.connLock.RLock()
		if session.localConn != nil {
			session.localConn.Close()
		}
		session.connLock.RUnlock()
		if session.localConn != nil {
			session.localConn.Close()
		}
		if session.localUdpConn != nil {
			session.localUdpConn.Close()
		}
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
		old.connLock.RLock()
		if old.localConn != nil {
			old.localConn.Close()
		}
		old.connLock.RUnlock()
	} else {
		sc.sessions[sessionId] = session
	}
	return sessionId
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
	case eTunnel_error:
		log.Println("tunnel error", content, sessionId)
		go sc.removeSession(sessionId)
	case eShowandquit:
		println(content)
		sc.Quit()
	case eTunnel_msg_s:
		if sc.bUdp {
			if sc.listenerUdp != nil && session != nil {
				sc.listenerUdp.WriteToUDP([]byte(content), session.localUdpAddr)
			}
			return
		}
		if conn != nil {
			if sc.stimeout > 0 {
				timeNow.RLock()
				session.dieT = timeNow.Add(time.Duration(sc.stimeout) * time.Second)
				timeNow.RUnlock()
			}
			conn.Write([]byte(content))
			timeNow.RLock()
			pinfo.Add(int64(len(content)), timeNow.Unix())
			timeNow.RUnlock()
		} else {
			//log.Println("cannot tunnel msg", sessionId)
		}
	case eTunnel_close_s:
		go sc.removeSession(sessionId)
	case eInit_action_back:
		log.Println("server force do action", content)
		sc.action, sc.bUdp = checkUdp(content)
	case eInit_action:
		sc.action = content
		log.Println("init action", content)
		sc.action, sc.bUdp = checkUdp(content)
		if *remoteAction != "" && *remoteAction != sc.action {
			sc.action, sc.bUdp = checkUdp(*remoteAction)
			go common.WriteCrypt(pipe, sessionId, eInit_action_back, []byte(*remoteAction), sc.encode)
		}
	case eReverse:
		sc.reverseAddr = content
		go sc.MultiListen()
	case eReady:
		currReadyId++
		sc.readyId = strconv.Itoa(currReadyId)
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
						go sc.MultiListen()
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
				for i := 1; i < maxPipes; i++ {
					c.pipesLock.RLock()
					_, b := c.pipes[i]
					c.pipesLock.RUnlock()
					if !b {
						timeNow.RLock()
						now := timeNow.Unix()
						timeNow.RUnlock()
						c.pipesLock.Lock()
						c.pipes[i] = &pipeInfo{conn: pipe, total: 0, t: now, owner: nil, newindex: 0}
						c.pipesLock.Unlock()
						newindex := 0
						sc.pipesLock.RLock()
						for _i, _info := range sc.pipes {
							if _info.conn == pipe {
								_info.Lock()
								_info.newindex = i
								_info.owner = c
								_info.Unlock()
								newindex = _i
								break
							}
						}
						sc.pipesLock.RUnlock()
						log.Println("collect", sc.id, "pipe", newindex, "=>", c.id, "pipe", i)
						break
					}
				}
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
	case eTunnel_msg_c_udp:
		if session !=nil && session.localUdpConn != nil {
			//log.Println("tunnel", (content), sessionId)
			timeNow.RLock()
			if sc.stimeout > 0 {
				session.dieT = timeNow.Add(time.Duration(sc.stimeout) * time.Second)
			}
			pinfo.Add(int64(len(content)), timeNow.Unix())
			timeNow.RUnlock()
			session.localUdpConn.WriteToUDP([]byte(content), session.localUdpAddr)
		}
	case eTunnel_msg_c:
		if conn != nil {
			//log.Println("tunnel", (content), sessionId)
			timeNow.RLock()
			if sc.stimeout > 0 {
				session.dieT = timeNow.Add(time.Duration(sc.stimeout) * time.Second)
			}
			pinfo.Add(int64(len(content)), timeNow.Unix())
			timeNow.RUnlock()
			conn.Write([]byte(content))
		}
	case eTunnel_close:
		go sc.removeSession(sessionId)
	case eTunnel_open:
		if sc.action != "socks5" {
			remote := sc.action
			if sc.bUdp {
				sock, _err := net.ListenUDP("udp", &net.UDPAddr{})
				if _err != nil {
					log.Println("dial addr fail", _err.Error())
					msg := _err.Error()
					go common.WriteCrypt(pipe, sessionId, eTunnel_error, []byte(msg), sc.encode)
					return
				}
				timeNow.RLock()
				udpAddr, err := net.ResolveUDPAddr("udp", sc.action)
				if err != nil {
					log.Println("resolve addr fail", err.Error())
					msg := err.Error()
					go common.WriteCrypt(pipe, sessionId, eTunnel_error, []byte(msg), sc.encode)
					return
				}

				session := &clientSession{pipe: pinfo, localUdpConn: sock, dieT: timeNow.Add(time.Duration(sc.stimeout) * time.Second), localUdpAddr: udpAddr}
				timeNow.RUnlock()
				sc.createSession(sessionId, session)
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
								timeNow.RLock()
								session.pipe.Add(int64(n), timeNow.Unix())
								timeNow.RUnlock()
							}
						}
					}
					sc.removeSession(sessionId)
					common.WriteCrypt(pinfo.conn, sessionId, eTunnel_close_s, []byte{}, sc.encode)
				}()
				return
			}
			if sc.action == "route" {
				remote = content
			}
			s_conn, err := net.DialTimeout("tcp", remote, 10*time.Second)
			if err != nil {
				log.Println("connect to local server fail:", err.Error(), remote)
				msg := "cannot connect to bind addr" + remote
				go common.WriteCrypt(pipe, sessionId, eTunnel_error, []byte(msg), sc.encode)
				return
			} else {
				timeNow.RLock()
				session := &clientSession{pipe: pinfo, localConn: s_conn, dieT: timeNow.Add(time.Duration(sc.stimeout) * time.Second)}
				timeNow.RUnlock()
				sc.createSession(sessionId, session)
				go session.handleLocalPortResponse(sc, sessionId, "")
			}
		} else {
			timeNow.RLock()
			session = &clientSession{pipe: pinfo, localConn: nil, status: "init", recvMsg: "", dieT: timeNow.Add(time.Duration(sc.stimeout) * time.Second)}
			timeNow.RUnlock()
			sc.createSession(sessionId, session)
			go func() {
				var hello reqMsg
				bOk, _ := hello.read([]byte(content))
				if !bOk {
					msg := "hello read err"
					go common.WriteCrypt(pipe, sessionId, eTunnel_error, []byte(msg), sc.encode)
					return
				}
				var ansmsg ansMsg
				url := hello.url
				var s_conn net.Conn
				var err error
				if *dnsCacheNum > 0 && hello.atyp == 3 {
					host := string(hello.dst_addr[1 : 1+hello.dst_addr[0]])
					resChan := make(chan *dnsQueryRes)
					debug("try cache", resChan)
					checkDns <- &dnsQueryReq{c: resChan, host: host, port: int(hello.dst_port2), reqtype: hello.reqtype, url: url}
					debug("try cache2")
					res := <-resChan
					debug("try cache3")
					s_conn = res.conn
					err = res.err
					if res.ip != "" {
						url = net.JoinHostPort(res.ip, fmt.Sprintf("%d", hello.dst_port2))
					}
				}
				if s_conn == nil && err == nil {
					//log.Println("try dial", url)
					s_conn, err = net.DialTimeout(hello.reqtype, url, 30*time.Second)
					//log.Println("try dial", url, "ok")
				}
				if err != nil {
					log.Println("connect to local server fail:", err.Error(), url)
					ansmsg.gen(&hello, 4)
					go common.WriteCrypt(pipe, sessionId, eTunnel_msg_s, ansmsg.buf[:ansmsg.mlen], sc.encode)
					timeNow.RLock()
					pinfo.Add(int64(ansmsg.mlen), timeNow.Unix())
					timeNow.RUnlock()
				} else {
					session.connLock.Lock()
					session.localConn = s_conn
					session.connLock.Unlock()
					go session.handleLocalPortResponse(sc, sessionId, hello.url)
					ansmsg.gen(&hello, 0)
					go common.WriteCrypt(pipe, sessionId, eTunnel_msg_s, ansmsg.buf[:ansmsg.mlen], sc.encode)
					timeNow.RLock()
					pinfo.Add(int64(ansmsg.mlen), timeNow.Unix())
					timeNow.RUnlock()
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
			timeNow.RLock()
			now := timeNow
			timeNow.RUnlock()
			for id, session := range sc.sessions {
				if now.After(session.dieT) {
					session.connLock.RLock()
					if session.localConn != nil {
						log.Println("try close timeout session connection", session.localConn.RemoteAddr(), id)
						session.localConn.Close()
					}
					if session.localUdpAddr != nil {
						log.Println("try close timeout udp session connection", session.localUdpAddr.String(), id)
						//delete(sc.sessions, id)
						common.WriteCrypt(session.pipe.conn, id, eTunnel_close, []byte{}, sc.encode)
						sc.removeSession(id)
					}
					session.connLock.RUnlock()
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
	if !sc.closed {
		sc.closed = true
	} else {
		return
	}
	close(sc.quit)
	for _, session := range sc.sessions {
		session.connLock.RLock()
		if session.localConn != nil {
			session.localConn.Close()
		}
		if session.localUdpConn != nil {
			session.localUdpConn.Close()
		}
		session.connLock.RUnlock()
	}
	log.Println("client quit", sc.id)
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
						log.Println("udp client over", e.Error())
						break
					}
				}
				pipe := sc.getOnePipe()
				if pipe == nil {
					log.Println("cannot get pipe for client, wait for recover...")
					time.Sleep(time.Second)
					continue
				}
				sessionId := genId([]byte(from.String()))
				session := sc.getSession(sessionId)
				if session == nil {
					timeNow.RLock()
					session = &clientSession{pipe: pipe, localUdpAddr: from, dieT: timeNow.Add(time.Duration(sc.stimeout) * time.Second)}
					timeNow.RUnlock()
					sc.createSession(sessionId, session)
					log.Println("create udp session", sessionId)
					common.WriteCrypt(pipe.conn, sessionId, eTunnel_open, tmp[:n], sc.encode)
				}
				if common.WriteCrypt(pipe.conn, sessionId, eTunnel_msg_c_udp, tmp[:n], sc.encode) != nil {
					break
				} else {
					timeNow.RLock()
					if sc.stimeout > 0 {
						session.dieT = timeNow.Add(time.Duration(sc.stimeout) * time.Second)
					}
					timeNow.RUnlock()
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
				if pipe == nil {
					log.Println("cannot get pipe for client, wait for recover...")
					time.Sleep(time.Second)
					continue
				}
				timeNow.RLock()
				session := &clientSession{pipe: pipe, localConn: conn, status: "init", dieT: timeNow.Add(time.Duration(sc.stimeout) * time.Second)}
				timeNow.RUnlock()
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
	timeNow.RLock()
	now := timeNow.Unix()
	timeNow.RUnlock()
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

///////////////////////multi pipe support
func (session *clientSession) handleLocalPortResponse(client *Client, id int, url string) {
	sessionId := id
	session.connLock.RLock()
	conn := session.localConn
	session.connLock.RUnlock()
	if conn == nil {
		return
	}
	arr := make([]byte, WriteBufferSize)
	debug("@@@@@@@ debug begin", url)
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
			timeNow.RLock()
			session.dieT = timeNow.Add(time.Duration(client.stimeout) * time.Second)
			timeNow.RUnlock()
		}
		debug("====debug read", size, url)
		if common.WriteCrypt(pipe, id, eTunnel_msg_s, arr[0:size], client.encode) != nil {
			break
		} else {
			timeNow.RLock()
			session.pipe.Add(int64(size), timeNow.Unix())
			timeNow.RUnlock()
		}
		debug("!!!!debug write", size, url)
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
		client.removeSession(sessionId)
		return
	}
	session.connLock.RLock()
	conn := session.localConn
	session.connLock.RUnlock()
	remote := ""
	if client.action == "route" {
		c := make(chan string)
		checkRealAddrChan <- &queryRealAddrInfo{conn, c}
		remote = <-c
		if remote == "" {
			client.removeSession(sessionId)
			return
		}
	}
	if client.action != "socks5" {
		common.WriteCrypt(pipe, sessionId, eTunnel_open, []byte(remote), client.encode)
	}
	arr := make([]byte, buffSize)
	reader := bufio.NewReader(conn)
	bParsed := false
	bNeedBreak := false
	var recv string
	var host string

	for {
		size, err := reader.Read(arr)
		if err != nil {
			break
		}
		if client.stimeout > 0 {
			timeNow.RLock()
			session.dieT = timeNow.Add(time.Duration(client.stimeout) * time.Second)
			timeNow.RUnlock()
		}
		if client.action == "socks5" && !bParsed {
			session.processSockProxy(sessionId, string(arr[0:size]), func(head []byte, _host string) {
				host = _host
				common.WriteCrypt(pipe, sessionId, eTunnel_open, head, client.encode)
				if common.WriteCrypt(pipe, sessionId, eTunnel_msg_c, []byte(session.recvMsg), client.encode) != nil {
					bNeedBreak = true
				} else {
					timeNow.RLock()
					session.pipe.Add(int64(len(session.recvMsg)), timeNow.Unix())
					timeNow.RUnlock()
					if *bCache {
						recv += session.recvMsg
					}
				}
				bParsed = true
			})
		} else {
			if common.WriteCrypt(pipe, sessionId, eTunnel_msg_c, arr[0:size], client.encode) != nil {
				bNeedBreak = true
			} else {
				timeNow.RLock()
				session.pipe.Add(int64(size), timeNow.Unix())
				timeNow.RUnlock()
				if *bCache && client.action == "socks5" {
					recv += string(arr[:size])
				}
			}
		}
		if bNeedBreak {
			break
		}
	}
	common.WriteCrypt(pipe, sessionId, eTunnel_close, []byte{}, client.encode)
	client.removeSession(sessionId)
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
