package main

import (
	"./common"
	"./nat"
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"
)

var serverAddr = flag.String("remote", "127.0.0.1:8000", "connect remote server")
var addInitAddr = flag.String("addip", "127.0.0.1", "addip for bust,xx.xx.xx.xx;xx.xx.xx.xx;")

var serveName = flag.String("reg", "", "reg the name for client link, must assign regname or linkname")

var linkName = flag.String("link", "", "name for link, must assign regname or linkname")
var localAddr = flag.String("local", "", "addr for listen or connect,depends on linkname or regname")
var bVerbose = flag.Bool("v", false, "verbose mode")
var delayTime = flag.Int("delay", 0, "if bust fail, try to make some delay seconds")
var pipeNum = flag.Int("pipenum", 1, "client pipe num")
var clientMode = flag.Int("mode", 0, "connect mode:0 if p2p fail, use c/s mode;1 just p2p mode;2 just c/s mode")
var bUseSSL = flag.Bool("ssl", false, "use ssl")
var bShowVersion = flag.Bool("version", false, "show version")

var remoteConn net.Conn
var clientType = -1

var g_ClientMap map[string]*Client
var markName = ""
var bForceQuit = false
var currDelayTime = 0

func handleResponse(conn net.Conn, clientId string, action string, content string) {
	//log.Println("got", clientId, action)
	switch action {
	case "show":
		log.Println(content)
	case "showandquit":
		fmt.Println(time.Now().String(), content)
		remoteConn.Close()
		bForceQuit = true
	case "clientquit":
		client := g_ClientMap[clientId]
		log.Println("clientquit!!!", clientId, client)
		if client != nil {
			client.Quit()
		}
	case "query_addrlist_a":
		outip := content
		go reportAddrList(clientId, true, outip)
	case "query_addrlist_b":
		go reportAddrList(clientId, false, content)
	case "tell_bust_a":
		go beginMakeHole(clientId, content)
	case "tell_bust_b":
		go beginMakeHole(clientId, "")
	case "csmode_s_tunnel_close":
		arr := strings.Split(clientId, "-")
		clientId = arr[0]
		sessionId := arr[1]
		client, bHave := g_ClientMap[clientId]
		if bHave {
			conn, bHave := client.local_conns[sessionId]
			if bHave {
				conn.Close()
				delete(client.local_conns, sessionId)
			}
		}
	case "csmode_s_tunnel_open":
		oriId := clientId
		arr := strings.Split(oriId, "-")
		clientId = arr[0]
		sessionId := arr[1]
		client, bHave := g_ClientMap[clientId]
		if !bHave {
			client = &Client{id: clientId, local_conns: make(map[string]net.Conn), engine: nil, buster: true, conn: remoteConn, ready: true, bUdp: false}
			g_ClientMap[clientId] = client
		} else {
			if client.local_conns == nil {
				client.local_conns = make(map[string]net.Conn)
			}
			client.conn = remoteConn
			client.ready = true
			client.bUdp = false
		}
		log.Println("client init csmode", clientId, sessionId)
		s_conn, err := net.DialTimeout("tcp", *localAddr, 10*time.Second)
		if err != nil {
			log.Println("connect to local server fail:", err.Error())
			msg := "cannot connect to bind addr" + *localAddr
			common.Write(remoteConn, clientId, "tunnel_error", msg)
			//remoteConn.Close()
			return
		} else {
			oldConn, bHave := client.local_conns[sessionId]
			if bHave {
				oldConn.Close()
			}
			client.local_conns[sessionId] = s_conn
			go handleLocalPortResponse(client, s_conn, oriId)
		}
	case "csmode_c_begin":
		client, bHave := g_ClientMap[clientId]
		if !bHave {
			client = &Client{id: clientId, engine: nil, buster: false, conn: remoteConn, ready: true, bUdp: false}
			g_ClientMap[clientId] = client
		} else {
			client.conn = remoteConn
			client.ready = true
			client.bUdp = false
		}
		if client.Listen() {
			common.Write(remoteConn, clientId, "makeholeok", "")
		}
	case "csmode_msg_c":
		arr := strings.Split(clientId, "-")
		clientId = arr[0]
		sessionId := arr[1]
		client, bHave := g_ClientMap[clientId]
		if bHave {
			conn, bHave := client.local_conns[sessionId]
			if bHave {
				conn.Write([]byte(content))
			}
		}
	case "csmode_msg_s":
		arr := strings.Split(clientId, "-")
		clientId = arr[0]
		sessionId := arr[1]
		client, bHave := g_ClientMap[clientId]
		if bHave {
			conn, bHave := client.serve_conns[sessionId]
			if bHave {
				conn.Write([]byte(content))
			} else {
				log.Println("cannot tunnel msg")
			}
		}
	}
}

func disconnect() {
	if remoteConn != nil {
		remoteConn.Close()
		remoteConn = nil
	}
}

func reportAddrList(clientId string, buster bool, outip string) {
	client, bHave := g_ClientMap[clientId]
	if bHave {
		client.Quit()
	}
	var otherAddrList string
	if !buster {
		arr := strings.SplitN(outip, ":", 2)
		outip, otherAddrList = arr[0], arr[1]
	} else {
		arr := strings.SplitN(outip, ":", 2)
		var delayTime string
		outip, delayTime = arr[0], arr[1]
		currDelayTime, _ = strconv.Atoi(delayTime)
		if currDelayTime < 0 {
			currDelayTime = 0
		}
	}
	outip += ";" + *addInitAddr
	engine, err := nat.Init(outip, buster)
	if err != nil {
		println("init error", err.Error())
		disconnect()
		return
	}
	addrList := engine.GetAddrList()
	common.Write(remoteConn, clientId, "report_addrlist", addrList)
	client = &Client{id: clientId, engine: engine, buster: buster, ready: false, bUdp: true}
	g_ClientMap[clientId] = client
	if !buster {
		engine.SetOtherAddrList(otherAddrList)
	}
}

func main() {
	flag.Parse()
	if *bShowVersion {
		fmt.Printf("%.2f\n", common.Version)
		return
	}
	if !*bVerbose {
		log.SetOutput(ioutil.Discard)
	}
	if *serveName == "" && *linkName == "" {
		println("you must assign reg or link")
		return
	}
	if *serveName != "" && *linkName != "" {
		println("you must assign reg or link, not both of them")
		return
	}
	if *localAddr == "" {
		println("you must assign the local addr")
		return
	}
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, os.Kill)
		for {
			<-c
			log.Println("received signal,shutdown")
			bForceQuit = true
			if remoteConn != nil {
				remoteConn.Close()
			}
		}
	}()

	loop := func() bool {
		if bForceQuit {
			return true
		}
		g_ClientMap = make(map[string]*Client)
		//var err error
		if *bUseSSL {
			_remoteConn, err := tls.Dial("tcp", *serverAddr, &tls.Config{InsecureSkipVerify: true})
			if err != nil {
				println("connect remote err:" + err.Error())
				return false
			}
			remoteConn = net.Conn(_remoteConn)
		} else {
			_remoteConn, err := net.DialTimeout("tcp", *serverAddr, 10*time.Second)
			if err != nil {
				println("connect remote err:" + err.Error())
				return false
			}
			remoteConn = _remoteConn
		}
		println("connect to server succeed")
		go connect()
		go func() {
			c := time.Tick(time.Second * 10)
			for _ = range c {
				if remoteConn == nil {
					break
				}
				if common.Write(remoteConn, "-1", "ping", "") != nil {
					break
				}
			}
		}()

		common.Read(remoteConn, handleResponse)
		for clientId, client := range g_ClientMap {
			log.Println("client shutdown", clientId)
			client.Quit()
		}

		remoteConn.Close()
		if bForceQuit {
			return true
		}
		return false
	}
	if *serveName != "" {
		clientType = 0
		for {
			if loop() {
				break
			}
			time.Sleep(10 * time.Second)
		}
	} else {
		clientType = 1
		loop()
	}
	log.Println("service shutdown")
}

func connect() {
	clientInfo := common.ClientSetting{Version: common.Version, Delay: *delayTime, Mode: *clientMode}
	if clientType == 0 {
		markName = *serveName
		clientInfo.ClientType = "reg"
	} else if clientType == 1 {
		markName = *linkName
		clientInfo.ClientType = "link"
	} else {
		println("no clienttype!")
	}
	clientInfo.Name = markName
	clientInfoStr, err := json.Marshal(clientInfo)
	if err != nil {
		println("encode args error")
	}
	log.Println("init client", string(clientInfoStr))
	common.Write(remoteConn, "0", "init", string(clientInfoStr))
}

type Client struct {
	id             string
	buster         bool
	engine         *nat.AttemptEngine
	conn           net.Conn            // tunnel pipe
	local_conns    map[string]net.Conn // client for local pipe
	serve_listener net.Listener        // service pipe
	serve_conns    map[string]net.Conn // client for service pipe
	ready          bool
	bUdp           bool
}

func (sc *Client) OnTunnelRecv(sessionId string, action string, content string) {
	//print("recv p2p tunnel", sessionId, action, content)
	switch action {
	case "tunnel_error":
		conn, bHave := sc.local_conns[sessionId]
		if bHave {
			conn.Write([]byte(content))
			log.Println("tunnel error", content, sessionId)
			conn.Close()
		}
	//case "serve_begin":
	case "tunnel_msg_s":
		conn, bHave := sc.serve_conns[sessionId]
		if bHave {
			conn.Write([]byte(content))
		} else {
			log.Println("cannot tunnel msg")
		}
	case "tunnel_msg_c":
		conn, bHave := sc.local_conns[sessionId]
		if bHave {
			conn.Write([]byte(content))
		}
	case "tunnel_close":
		conn, bHave := sc.local_conns[sessionId]
		if bHave {
			log.Println("tunnel close", content, sessionId)
			conn.Close()
			delete(sc.local_conns, sessionId)
		}
	case "tunnel_open":
		if clientType == 0 {
			s_conn, err := net.DialTimeout("tcp", *localAddr, 10*time.Second)
			if err != nil {
				log.Println("connect to local server fail:", err.Error())
				msg := "cannot connect to bind addr" + *localAddr
				common.Write(sc.conn, sessionId, "tunnel_error", msg)
				//remoteConn.Close()
				return
			} else {
				sc.local_conns[sessionId] = s_conn
				go handleLocalPortResponse(sc, s_conn, sessionId)
			}

		}
	}
}

func (sc *Client) Quit() {
	log.Println("client quit", sc.id)
	delete(g_ClientMap, sc.id)
	if sc.conn != nil && sc.conn != remoteConn {
		sc.conn.Close()
	}
	if sc.serve_conns != nil {
		for sessionId, conn := range sc.serve_conns {
			conn.Close()
			common.RmId("udp", sessionId)
			log.Println("shutdown session", sessionId)
		}
	}
	if sc.local_conns != nil {
		for sessionId, conn := range sc.local_conns {
			conn.Close()
			log.Println("shutdown session", sessionId)
		}
	}
	sc.serve_conns = nil
	sc.local_conns = nil
	if sc.serve_listener != nil {
		sc.serve_listener.Close()
	}
	if sc.engine != nil {
		sc.engine.Fail()
	}
}

func (sc *Client) Listen() bool {
	sc.serve_conns = make(map[string]net.Conn)
	serveConn, err := net.Listen("tcp", *localAddr)
	if err != nil {
		log.Println("cannot listen addr:" + err.Error())
		remoteConn.Close()
		return false
	}
	sc.serve_listener = serveConn
	go func() {
		for {
			conn, err := serveConn.Accept()
			if err != nil {
				continue
			}
			sessionId := common.GetId("udp")
			sc.serve_conns[sessionId] = conn
			go handleLocalServerResponse(sc, conn, sessionId)
		}
	}()
	mode := "udp mode"
	if !sc.bUdp {
		mode = "c/s mode"
	}
	println("service start success,please connect", *localAddr, mode)
	return true
}

func (sc *Client) Run() {
	if clientType == 0 {
		sc.local_conns = make(map[string]net.Conn)
	}
	//go func() {
	//}()
	go func() {
		callback := func(conn net.Conn, sessionId, action, content string) {
			if sc != nil {
				sc.OnTunnelRecv(sessionId, action, content)
			}
		}
		common.Read(sc.conn, callback)
		log.Println("client end read")
		if clientType == 1 {
			remoteConn.Close()
		}
	}()
}

func (sc *Client) LocalAddr() net.Addr                { return nil }
func (sc *Client) Close() error                       { return nil }
func (sc *Client) RemoteAddr() net.Addr               { return nil }
func (sc *Client) SetDeadline(t time.Time) error      { return nil }
func (sc *Client) SetReadDeadline(t time.Time) error  { return nil }
func (sc *Client) SetWriteDeadline(t time.Time) error { return nil }

func beginMakeHole(clientId string, content string) {
	client, bHave := g_ClientMap[clientId]
	if !bHave {
		println("error, no client,id is", clientId)
		return
	}
	engine := client.engine
	addrList := content
	if client.buster {
		engine.SetOtherAddrList(addrList)
	}
	log.Println("begin bust", clientId, client.buster)
	if !client.buster {
		println("retry bust!")
	}
	report := func() {
		if client.buster {
			if currDelayTime > 0 {
				log.Println("try to delay", currDelayTime, "seconds")
				time.Sleep(time.Duration(currDelayTime) * time.Second)
			}
			go common.Write(remoteConn, clientId, "success_bust_a", "")
		}
	}
	oldClient := client
	conn, err := engine.GetConn(report)
	client, bHave = g_ClientMap[clientId]
	if client != oldClient {
		return
	}
	if bHave && client.ready {
		return
	}
	if err == nil {
		client.ready = true
		log.Println("udp bust ok,is server?", client.buster)
		if !client.buster {
			common.Write(remoteConn, client.id, "makeholeok", "")
		}
		client.conn = conn
		go client.Run()
		if clientType == 1 {
			client.Listen()
		}
	} else {
		log.Println("cannot connect", err.Error())
		//client.Quit()
		if bHave && !client.buster && err.Error() != "quit" {
			common.Write(remoteConn, client.id, "makeholefail", "")
		}
	}
}

func handleLocalPortResponse(client *Client, conn net.Conn, id string) {
	arr := make([]byte, 1000)
	reader := bufio.NewReader(conn)
	for {
		size, err := reader.Read(arr)
		if err != nil {
			break
		}
		if common.Write(client.conn, id, "tunnel_msg_s", string(arr[0:size])) != nil {
			break
		}
	}
	// log.Println("handlerlocal down")
	conn.Close()
}

func handleLocalServerResponse(client *Client, conn net.Conn, sessionId string) {
	common.Write(client.conn, sessionId, "tunnel_open", "")
	arr := make([]byte, 1000)
	reader := bufio.NewReader(conn)
	for {
		size, err := reader.Read(arr)
		if err != nil {
			break
		}
		if common.Write(client.conn, sessionId, "tunnel_msg_c", string(arr[0:size])) != nil {
			break
		}
	}
	log.Println("handlerlocal down", sessionId)
	common.Write(client.conn, sessionId, "tunnel_close", "")
	common.RmId("udp", sessionId)
	delete(client.serve_conns, sessionId)
}
