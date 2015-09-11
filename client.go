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
	"os"
	"os/signal"
	"os/user"
	"path"
	"runtime"
	//de "runtime/debug"
	//"runtime/pprof"
	"strconv"
	"strings"
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
	eS_timeout
	eShowandquit
	eReady
	eReadyback
	eReverse
	eSettimeout
	eTunnel_error
	eTunnel_msg_s
	eTunnel_close_s
	eTunnel_msg_c
	eTunnel_close
	eTunnel_open
)

//var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")

var authKey = flag.String("auth", "", "key for auth")
var pipeN = flag.Int("pipe", 1, "pipe num(todo...)")
var threadN = flag.Int("thread", 1, "replace of GOMAXPROCS")
var bTcp = flag.Bool("tcp", false, "use tcp to replace udp")
var xorData = flag.String("xor", "", "xor key,c/s must use a some key")

var serviceAddr = flag.String("service", "", "listen addr for client connect")
var localAddr = flag.String("local", "", "if local not empty, treat me as client, this is the addr for local listen, otherwise, treat as server")
var remoteAction = flag.String("action", "socks5", "for client control server, if action is socks5,remote is socks5 server, if is addr like 127.0.0.1:22, remote server is a port redirect server,\"route\" is for transparent socks")
var bVerbose = flag.Bool("v", false, "verbose mode")
var bShowVersion = flag.Bool("version", false, "show version")
var bEncrypt = flag.Bool("encrypt", false, "p2p mode encrypt")
var dnsCacheNum = flag.Int("dnscache", 0, "if > 0, dns will cache xx minutes")
var timeOut = flag.Int("timeout", 100, "udp pipe set timeout(seconds)")

var bListenUdp = flag.Bool("listenudp", false, "listen udp mode")
var bDebug = flag.Int("debug", 0, "more output log")
var bReverse = flag.Bool("r", false, "reverse mode, if true, client 's \"-local\" address will be listened on server side")
var sessionTimeout = flag.Int("session_timeout", 0, "if > 0, session will check itself if it's alive, if no msg tranfer for some seconds, socket will be closed, use this to avoid of zombie tcp sockets")

var clientType = 1
var currReadyId = 0

const maxPipes = 10

var clientReportSessionChan chan int
var timeNow time.Time

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
	return timeNow.Unix() < u.overTime
}

func (u *dnsInfo) SetCacheTime(t int64) {
	if t >= 0 {
		u.cacheTime = t
	} else {
		t = u.cacheTime
	}
	u.overTime = t + timeNow.Unix()
}

func (u *dnsInfo) GetCacheTime() int64 {
	return u.overTime
}

func (u *dnsInfo) DeInit() {}

var g_ClientMap map[string]*Client
var markName = ""
var bForceQuit = false

var aesIV []byte

func initAesIV() {
	aesIV = make([]byte, aes.BlockSize)
	for i := 0; i < aes.BlockSize; i++ {
		aesIV[i] = byte(i)
	}
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
	client, bHave := g_ClientMap[id]
	if !bHave {
		client = &Client{id: id, ready: true, bUdp: !bIsTcp, sessions: make(map[int]*clientSession), pipes: make(map[int]*pipeInfo), quit: make(chan bool), createSessionChan: make(chan createSessionInfo), removeSessionChan: make(chan removeSessionInfo), getSessionChan: make(chan getSessionInfo)}
		go client.sessionLoop()
		g_ClientMap[id] = client
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
			encrypt_tail = string([]byte(fmt.Sprintf("%d%d", int32(timeNow.Unix()), (rand.Intn(100000) + 100)))[:12])
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
	client.action = *remoteAction
	common.WriteCrypt(s_conn, -1, eInit_action, []byte(*remoteAction), client.encode)
	client.stimeout = *sessionTimeout

	pinfo := &pipeInfo{s_conn, 0, timeNow.Unix(), nil, 0}
	client.pipes[idindex] = pinfo
	clientReportSessionChan <- idindex
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
	clientReportSessionChan <- -1
	delete(client.pipes, idindex)
	s_conn.Close()
	if len(client.pipes) == 0 {
		client.Quit()
	}
	return true
}
func Listen(bIsTcp bool, addr string) bool {
	var err error
	if bIsTcp {
		g_LocalConn, err = net.Listen("tcp", addr)
	} else {
		g_LocalConn, err = pipe.Listen(addr)
	}
	if err != nil {
		g_LocalConn = nil
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
		client, have := g_ClientMap[id]
		if !have {
			client = &Client{id: id, ready: true, bUdp: bIsTcp, sessions: make(map[int]*clientSession), pipes: make(map[int]*pipeInfo), quit: make(chan bool), createSessionChan: make(chan createSessionInfo), removeSessionChan: make(chan removeSessionInfo), getSessionChan: make(chan getSessionInfo)}
			go client.sessionLoop()
			g_ClientMap[id] = client
			if *authKey == "" {
				client.authed = true
			}
		}

		idindex := -1
		for i := 0; i < maxPipes; i++ {
			_, bHave := client.pipes[i]
			if !bHave {
				idindex = i
				client.pipes[i] = &pipeInfo{conn, 0, timeNow.Unix(), nil, 0}
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
	g_LocalConn = nil
	return true
}

func (client *Client) ServerProcess(bIsTcp bool, idindex int) {
	pipeInfo, _ := client.pipes[idindex]
	f := func() {
		if pipeInfo.owner != nil {
			old := client.id
			delete(client.pipes, idindex)
			if len(client.pipes) == 0 {
				client._Quit()
			}
			idindex = pipeInfo.newindex
			client = pipeInfo.owner
			pipeInfo.owner = nil
			log.Println(old, "pipe >>", client.id, idindex)
			pipeInfo, _ = client.pipes[idindex]
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
	delete(client.pipes, idindex)
	conn.Close()
	if bIsTcp {
		log.Println("remove tcp pipe", idindex, "for", client.id)
	} else {
		log.Println("remove udp pipe", idindex, "for", client.id)
	}
	if len(client.pipes) == 0 {
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

type createSessionInfo struct {
	sessionId int
	session   *clientSession
	c         chan int
}

type removeSessionInfo struct {
	sessionId int
	c         chan bool
}

type getSessionInfo struct {
	sessionId int
	c         chan *clientSession
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
					_cacheInfo.Ip = strings.Split(info.conn.RemoteAddr().String(), ":")[0]
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
			timeNow = time.Now()
		}
	}()
	timeNow = time.Now()
	rand.Seed(timeNow.Unix())
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
	g_ClientMap = make(map[string]*Client)
	if *bDebug > 0 {
		go func() {
			c := time.NewTicker(time.Second * 15)
			for _ = range c.C {
				log.Println("begin =====")
				now := timeNow.Unix()
				for addr, client := range g_ClientMap {
					var rate float64 = 0
					for _, pipeInfo := range client.pipes {
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
					}
					log.Println("----", addr, len(client.pipes), "pipes;", len(client.sessions), "sessions;", int64(rate), "bytes/second;")
				}
				log.Println("end =====")
			}
			if g_LocalConn != nil && *bTcp {
				g_LocalConn.(*pipe.Listener).Dump()
			}
		}()
	}
	var w sync.WaitGroup
	w.Add(2)
	pipen := 0
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
			for _, client := range g_ClientMap {
				client.Quit()
				pipen = 0
			}
			if g_LocalConn != nil {
				g_LocalConn.Close()
			}
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
			clientReportSessionChan = make(chan int)
			bDropFromZero := true
			go func() {
				for {
					select {
					case r := <-clientReportSessionChan:
						if r >= 0 {
							pipen++
							if pipen == *pipeN {
								client, bHave := g_ClientMap[*serviceAddr]
								if bHave {
									pipeInfo, bH := client.pipes[r]
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
							pipen--
							if pipen <= 0 {
								bDropFromZero = true
								pipen = 0
								client, bHave := g_ClientMap[*serviceAddr]
								if bHave {
									client.Quit()
								}
							} else {
								bDropFromZero = false
							}
						}
					}
				}
			}()
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
	pipe      *pipeInfo
	localConn net.Conn
	status    string
	recvMsg   string
	extra     uint8
	dieT      time.Time
}

func (session *clientSession) processSockProxy(sessionId int, content string, callback func([]byte)) {
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
		go session.localConn.Write(send)
		session.status = "hello"
		session.recvMsg = string(bytes[session.extra:])
		session.extra = 0
	case "hello":
		var hello reqMsg
		bOk, tail := hello.read(bytes)
		if bOk {
			session.status = "ok"
			session.recvMsg = string(tail)
			callback(bytes)
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

func (msg *ansMsg) gen(req *reqMsg, rep, atyp uint8) {
	msg.ver = 5
	msg.rep = rep //rfc1928
	msg.rsv = 0
	msg.atyp = atyp //req.atyp

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
		msg.url = string(msg.dst_addr[1 : 1+msg.dst_addr[0]])
		if len(msg.url) > 0 && []byte(msg.url)[0] != '[' {
			msg.url = "[" + msg.url + "]"
		}
		msg.url += fmt.Sprintf(":%d", msg.dst_port2)
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
}

func (pinfo *pipeInfo) Add(size, now int64) {
	if now-pinfo.t > 60 {
		pinfo.total = size
		pinfo.t = now
	} else {
		pinfo.total += size
	}
}

type Client struct {
	id                string
	buster            bool
	pipes             map[int]*pipeInfo      // client for pipes
	sessions          map[int]*clientSession // session to pipeid
	ready             bool
	bUdp              bool
	action            string
	quit              chan bool
	closed            bool
	encode, decode    func([]byte) []byte
	authed            bool
	localconn         net.Conn
	listener          net.Listener
	reverseAddr       string
	readyId           string
	newindex          int
	encryptstr        string
	createSessionChan chan createSessionInfo
	removeSessionChan chan removeSessionInfo
	getSessionChan    chan getSessionInfo
	stimeout          int
}

// pipe : client to client
// local : client to local apps
func (sc *Client) getSession(sessionId int) *clientSession {
	if sessionId < 0 {
		return nil
	}
	c := make(chan *clientSession)
	request := getSessionInfo{sessionId, c}
	select {
	case sc.getSessionChan <- request:
	case <-sc.quit:
		return nil
	}
	session := <-c
	return session
}

func (sc *Client) removeSession(sessionId int) bool {
	c := make(chan bool)
	request := removeSessionInfo{sessionId, c}
	select {
	case sc.removeSessionChan <- request:
	case <-sc.quit:
		return false
	}
	return <-c
}

func (sc *Client) OnTunnelRecv(pipe net.Conn, sessionId int, action byte, content string, pinfo *pipeInfo) {
	debug("recv p2p tunnel", sessionId, action, len(content))
	session := sc.getSession(sessionId)
	var conn net.Conn
	if session != nil {
		conn = session.localConn
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
		if conn != nil {
			if sc.stimeout > 0 {
				session.dieT = timeNow.Add(time.Duration(sc.stimeout) * time.Second)
			}
			conn.Write([]byte(content))
			pinfo.Add(int64(len(content)), timeNow.Unix())
		} else {
			//log.Println("cannot tunnel msg", sessionId)
		}
	case eTunnel_close_s:
		go sc.removeSession(sessionId)
	case eInit_action_back:
		log.Println("server force do action", content)
		sc.action = content
	case eS_timeout:
		sc.stimeout, _ = strconv.Atoi(content)
		if sc.stimeout > 0 {
			log.Println("init session timeout", sc.stimeout)
			go sc.sessionCheckDie()
		}
	case eInit_action:
		sc.action = content
		log.Println("init action", content)
		if *remoteAction != "" && *remoteAction != sc.action {
			sc.action = *remoteAction
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
			for i, pipeInfo := range sc.pipes {
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
		}()
	case eCollect:
		readyId := content
		for _, c := range g_ClientMap {
			if c.readyId == readyId {
				log.Println("collect", sc.id, "=>", c.id, readyId)
				for i := 1; i < maxPipes; i++ {
					_, b := c.pipes[i]
					if !b {
						c.pipes[i] = &pipeInfo{pipe, 0, timeNow.Unix(), nil, 0}
						newindex := 0
						for _i, _info := range sc.pipes {
							if _info.conn == pipe {
								_info.newindex = i
								_info.owner = c
								newindex = _i
								break
							}
						}
						log.Println("collect", sc.id, "pipe", newindex, "=>", c.id, "pipe", i)
						break
					}
				}
				break
			}
		}
	case eInit_enc:
		tail := common.Xor(content)
		log.Println("got encrpyt key", tail)
		aesKey := "asd4" + tail
		aesBlock, _ := aes.NewCipher([]byte(aesKey))
		sc.SetCrypt(getEncodeFunc(aesBlock), getDecodeFunc(aesBlock))
	case eTunnel_msg_c:
		if conn != nil {
			//log.Println("tunnel", (content), sessionId)
			if sc.stimeout > 0 {
				session.dieT = timeNow.Add(time.Duration(sc.stimeout) * time.Second)
			}
			conn.Write([]byte(content))
			pinfo.Add(int64(len(content)), timeNow.Unix())
		}
	case eTunnel_close:
		go sc.removeSession(sessionId)
	case eTunnel_open:
		if sc.action != "socks5" {
			remote := sc.action
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
				session := &clientSession{pipe: pinfo, localConn: s_conn, dieT: timeNow.Add(time.Duration(sc.stimeout) * time.Second)}
				c := make(chan int)
				request := createSessionInfo{sessionId: sessionId, session: session, c: c}
				select {
				case sc.createSessionChan <- request:
					<-c
					go session.handleLocalPortResponse(sc, sessionId, "")
				case <-sc.quit:
				}
			}
		} else {
			session = &clientSession{pipe: pinfo, localConn: nil, status: "init", recvMsg: "", dieT: timeNow.Add(time.Duration(sc.stimeout) * time.Second)}
			c := make(chan int)
			request := createSessionInfo{sessionId: sessionId, session: session, c: c}
			select {
			case sc.createSessionChan <- request:
				<-c
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
							url = res.ip + fmt.Sprintf(":%d", hello.dst_port2)
						}
					}
					if s_conn == nil && err == nil {
						//log.Println("try dial", url)
						s_conn, err = net.DialTimeout(hello.reqtype, url, 30*time.Second)
						//log.Println("try dial", url, "ok")
					}
					if err != nil {
						log.Println("connect to local server fail:", err.Error(), url)
						ansmsg.gen(&hello, 4, hello.atyp)
						go common.WriteCrypt(pipe, sessionId, eTunnel_msg_s, ansmsg.buf[:ansmsg.mlen], sc.encode)
						pinfo.Add(int64(ansmsg.mlen), timeNow.Unix())
					} else {
						session.localConn = s_conn
						go session.handleLocalPortResponse(sc, sessionId, hello.url)
						ansmsg.gen(&hello, 0, hello.atyp)
						go common.WriteCrypt(pipe, sessionId, eTunnel_msg_s, ansmsg.buf[:ansmsg.mlen], sc.encode)
						pinfo.Add(int64(ansmsg.mlen), timeNow.Unix())
					}
				}()
			case <-sc.quit:
			}
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
			now := timeNow
			for id, session := range sc.sessions {
				if now.After(session.dieT) {
					if session.localConn != nil {
						log.Println("try close timeout session connection", session.localConn.RemoteAddr(), id)
						session.localConn.Close()
					}
				}
			}
		case <-sc.quit:
			break out
		}
	}
	t.Stop()
}

func (sc *Client) sessionLoop() {
out:
	for {
		select {
		case sessionInfo := <-sc.createSessionChan:
			if sessionInfo.sessionId == -1 {
				sessionInfo.sessionId = common.GetId("session")
			}
			old, bHave := sc.sessions[sessionInfo.sessionId]
			if bHave {
				if old.localConn != nil {
					old.localConn.Close()
				}
			} else {
				sc.sessions[sessionInfo.sessionId] = sessionInfo.session
			}
			sessionInfo.c <- sessionInfo.sessionId
		case sessionInfo := <-sc.removeSessionChan:
			common.RmId("session", sessionInfo.sessionId)
			session, bHave := sc.sessions[sessionInfo.sessionId]
			if bHave {
				delete(sc.sessions, sessionInfo.sessionId)
				if session.localConn != nil {
					session.localConn.Close()
				}
			}
			sessionInfo.c <- bHave
		case sessionInfo := <-sc.getSessionChan:
			session, bHave := sc.sessions[sessionInfo.sessionId]
			if bHave {
				sessionInfo.c <- session
			} else {
				sessionInfo.c <- nil
			}
		case <-sc.quit:
			for _, session := range sc.sessions {
				if session.localConn != nil {
					session.localConn.Close()
				}
			}
			break out

		}
	}
}

func (sc *Client) Quit() {
	sc._Quit()
	for id, pipeInfo := range sc.pipes {
		pipeInfo.conn.Close()
		delete(sc.pipes, id)
	}
	if sc.listener != nil {
		sc.listener.Close()
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
	log.Println("client quit", sc.id)
	delete(g_ClientMap, sc.id)
	//de.FreeOSMemory()
}

///////////////////////multi pipe support
var g_LocalConn net.Listener

func (sc *Client) MultiListen() bool {
	if sc.listener == nil {
		var err error
		sc.listener, err = net.Listen("tcp", sc.reverseAddr)
		if err != nil {
			log.Println("cannot listen addr:" + err.Error())
			for _, pipeInfo := range sc.pipes {
				common.WriteCrypt(pipeInfo.conn, -1, eShowandquit, []byte("cannot listen addr:"+err.Error()), sc.encode)
			}
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
				session := &clientSession{pipe: pipe, localConn: conn, status: "init", dieT: timeNow.Add(time.Duration(sc.stimeout) * time.Second)}
				c := make(chan int)
				request := createSessionInfo{sessionId: -1, session: session, c: c}
				select {
				case sc.createSessionChan <- request:
					sessionId := <-c
					//log.Println("client", sc.id, "create session", sessionId)
					go session.handleLocalServerResponse(sc, sessionId)
				case <-sc.quit:
				}
			}
			sc.listener = nil
			for _, pipeInfo := range sc.pipes {
				common.WriteCrypt(pipeInfo.conn, -1, eShowandquit, []byte("server listener quit"), sc.encode)
			}
		}()
	}
	return true
}

func (sc *Client) getOnePipe() *pipeInfo {
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
	now := timeNow.Unix()
	for _, info := range sc.pipes {
		dt := now - info.t
		if dt <= 0 {
			dt = 1
		}
		if dt > 60 {
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
	}
	//log.Println("choose pipe for ", choose, "of", size, min)
	return choose
}

///////////////////////multi pipe support
func (session *clientSession) handleLocalPortResponse(client *Client, id int, url string) {
	sessionId := id
	conn := session.localConn
	if conn == nil {
		return
	}
	arr := make([]byte, pipe.WriteBufferSize)
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
			session.dieT = timeNow.Add(time.Duration(client.stimeout) * time.Second)
		}
		debug("====debug read", size, url)
		if common.WriteCrypt(pipe, id, eTunnel_msg_s, arr[0:size], client.encode) != nil {
			break
		} else {
			session.pipe.Add(int64(size), timeNow.Unix())
		}
		debug("!!!!debug write", size, url)
	}
	// log.Println("handlerlocal down")
	client.removeSession(sessionId)
	common.WriteCrypt(pipe, sessionId, eTunnel_close_s, []byte{}, client.encode)
}

func (session *clientSession) handleLocalServerResponse(client *Client, sessionId int) {
	buffSize := pipe.WriteBufferSize
	var pipe net.Conn
	if session.pipe != nil {
		pipe = session.pipe.conn
	}
	if pipe == nil {
		client.removeSession(sessionId)
		return
	}
	conn := session.localConn
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
	for {
		size, err := reader.Read(arr)
		if err != nil {
			break
		}
		if client.stimeout > 0 {
			session.dieT = timeNow.Add(time.Duration(client.stimeout) * time.Second)
		}
		if client.action == "socks5" && !bParsed {
			session.processSockProxy(sessionId, string(arr[0:size]), func(head []byte) {
				common.WriteCrypt(pipe, sessionId, eTunnel_open, head, client.encode)
				if common.WriteCrypt(pipe, sessionId, eTunnel_msg_c, []byte(session.recvMsg), client.encode) != nil {
					bNeedBreak = true
				} else {
					session.pipe.Add(int64(len(session.recvMsg)), timeNow.Unix())
				}
				bParsed = true
			})
		} else {
			if common.WriteCrypt(pipe, sessionId, eTunnel_msg_c, arr[0:size], client.encode) != nil {
				bNeedBreak = true
			} else {
				session.pipe.Add(int64(size), timeNow.Unix())
			}
		}
		if bNeedBreak {
			break
		}
	}
	common.WriteCrypt(pipe, sessionId, eTunnel_close, []byte{}, client.encode)
	client.removeSession(sessionId)
}
