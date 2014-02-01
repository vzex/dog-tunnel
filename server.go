package main

import (
	"./common"
	"bufio"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"
)

type Session struct {
	id       string
	clientA  net.Conn
	clientB  net.Conn
	status   string
	overTime int64
	method   string
	setting  common.ClientSetting
	quit     chan bool
}

func getServerInfoByConn(conn net.Conn, cb_ok func(*ClientInfo), cb_fail func()) {
	info, bHave := g_Conn2ClientInfo[conn]
	if bHave {
		if info.isServer {
			cb_ok(info)
		} else {
			serverName := info.serverName
			getClientInfoByName(serverName, cb_ok, cb_fail)
		}
	} else {
		cb_fail()
	}
}
func getClientInfoByConn(conn net.Conn, cb_ok func(*ClientInfo), cb_fail func()) {
	info, bHave := g_Conn2ClientInfo[conn]
	if bHave {
		cb_ok(info)
	} else {
		cb_fail()
	}
}
func getClientInfoByName(serverName string, cb_ok func(*ClientInfo), cb_fail func()) {
	conn, bHave := g_ServerName2Conn[serverName]
	if bHave {
		getClientInfoByConn(conn, cb_ok, cb_fail)
		return
	} else {
		cb_fail()
	}
}

func (session *Session) restartSession(serverName string) {
	log.Println("restart session", session.id)
	session.method = "restart"
	session.quit <- true
	tmp := session.clientA
	session.clientA = session.clientB
	session.clientB = tmp
	session.startSession(serverName, session.id)
}

func (session *Session) String() string {
	return fmt.Sprintf("%s|delay:%d|status:%s|method:%s|clientA:%s|clientB:%s|", session.id, session.setting.Delay, session.status, session.method, session.clientA.RemoteAddr().String(), session.clientB.RemoteAddr().String())
}

func (session *Session) down() {
	if session.quit != nil {
		close(session.quit)
		session.quit = nil
	}
	session.status = "down"
}

func (session *Session) startCSMode() {
	//make sure clientA and clientB not exchanged
	session.method = "cs"
	clientConn := session.clientA
	session.status = "csmode_begin"
	common.Write(clientConn, session.id, "csmode_c_begin", "")
	session.loop()
}

func (session *Session) loop() {
	go func() {
		checkChan := time.Tick(10 * time.Second)
	out:
		for {
			select {
			case <-checkChan:
				//println("check lop session status", session.status)
				if time.Now().Unix() > session.overTime {
					if session.status != "ok" {
						if session.method == "udp" || session.method == "cs" {
							session.clientA.Close()
						} else {
							session.clientB.Close()
						}
					}
				}
			case <-session.quit:
				log.Println("session loop quit", session.id)
				break out
			}
		}
	}()
}

func (session *Session) startSession(serverName, sessionId string) {
	log.Println("start session", session.id, session.setting.Mode, serverName)
	udpSession := &UDPMakeSession{id: common.GetId("makehole"), clientA: session.clientA, clientB: session.clientB, sessionId: sessionId, serverName: serverName, status: "init"}
	getClientInfoByName(serverName, func(server *ClientInfo) {
		server.id2MakeSession[udpSession.id] = udpSession
	}, func() {})
	udpSession.beginMakeHole(0, "")
	session.overTime = time.Now().Add(60 * time.Second).Unix()
	session.loop()
}

func (s *ClientInfo) getSession(conn net.Conn) *Session {
	session, bHave := s.clientMap[conn]
	if bHave {
		return session
	} else {
		return nil
	}
}

func (s *ClientInfo) addClient(conn net.Conn, clientInfo common.ClientSetting) {
	id := common.GetId(s.serverName)
	s.clientMap[conn] = &Session{clientA: conn, clientB: s.conn, method: "udp", overTime: 0, status: "init", id: id, setting: clientInfo, quit: make(chan bool)}
	s.id2Session[id] = s.clientMap[conn]
	if s.clientMap[conn].setting.Mode == 2 {
		s.clientMap[conn].startCSMode()
	} else {
		s.clientMap[conn].startSession(s.serverName, id)
	}
}

func (s *ClientInfo) loop() {
	go func() {
		checkChan := time.Tick(10 * time.Second)
	out:
		for {
			select {
			case <-checkChan:
				if time.Now().Unix()-s.responseTime > 300 {
					log.Println("timeout,client loop quit", s.conn.RemoteAddr().String())
					break out
				}
			case <-s.quit:
				break out
			}
		}
		s.conn.Close()
	}()
}

func (s *ClientInfo) delClient(conn net.Conn) string {
	session, bHave := s.clientMap[conn]
	if bHave {
		common.Write(conn, "0", "showandquit", "server kick you out")
		id := session.id
		session.down()
		log.Println("remove client session", id)
		delete(s.id2Session, id)
		delete(s.clientMap, conn)
		common.RmId(s.serverName, id)
		return id
	}
	return ""
}

type UDPMakeSession struct {
	id         string
	clientA    net.Conn
	clientB    net.Conn
	sessionId  string
	status     string
	serverName string
}

func (udpsession *UDPMakeSession) beginMakeHole(step int, content string) {
	var session *Session = nil
	if udpsession.sessionId != "" {
		getClientInfoByName(udpsession.serverName, func(server *ClientInfo) {
			session = server.id2Session[udpsession.sessionId]
		}, func() {})
	}
	if session != nil && session.method == "cs" {
		return
	}
	id := udpsession.id
	clientA := udpsession.clientA
	clientB := udpsession.clientB
	if step == 0 {
		log.Println("===>>tell a to report addrlist", clientA.RemoteAddr().String(), udpsession.serverName, udpsession.id)
		delay := 0
		if session != nil {
			delay = session.setting.Delay
		}
		common.Write(clientA, id+"-"+udpsession.sessionId, "query_addrlist_a", clientA.RemoteAddr().(*net.TCPAddr).IP.String()+":"+strconv.Itoa(delay))
		if session != nil {
			session.status = "tella"
		}
		udpsession.status = "tella"
	} else if step == 1 {
		if udpsession.status == "tella" {
			udpsession.status = "atellb"
			if session != nil {
				session.status = "atellb"
			}
			log.Println("===>>tell b to report addlist,give b the a's addrlist", clientB.RemoteAddr().String(), udpsession.serverName, udpsession.id)
			common.Write(clientB, id+"-"+udpsession.sessionId, "query_addrlist_b", clientB.RemoteAddr().(*net.TCPAddr).IP.String()+":"+content)
		} else if udpsession.status == "atellb" {
			udpsession.status = "bust_start_a"
			if session != nil {
				session.status = "bust_start_a"
			}
			log.Println("=====>>tell a the b 's addrlist, and a start bust", clientA.RemoteAddr().String(), udpsession.serverName, udpsession.id)
			common.Write(clientA, id, "tell_bust_a", content)
		}
	} else if step == 2 {
		udpsession.status = "bust_start_b"
		if session != nil {
			session.status = "bust_start_b"
		}
		log.Println("======>>tell b start bust", clientB.RemoteAddr().String(), udpsession.serverName, udpsession.id)
		common.Write(clientB, id, "tell_bust_b", content)
	}
}

type ClientInfo struct {
	conn       net.Conn
	clientMap  map[net.Conn]*Session
	id2Session map[string]*Session

	userName     string
	responseTime int64

	quit chan bool

	isServer       bool
	serverName     string // is serverName != "", this client is a server!
	id2MakeSession map[string]*UDPMakeSession
}

type AdminInfo struct {
	conn net.Conn
}

var g_ServerName2Conn map[string]net.Conn
var g_Conn2ClientInfo map[net.Conn]*ClientInfo
var g_Conn2Admin map[net.Conn]*AdminInfo

var listenAddr = flag.String("addr", "0.0.0.0:8000", "server addr")
var bUseSSL = flag.Bool("ssl", false, "use ssl")
var certFile = flag.String("cert", "", "cert file")
var keyFile = flag.String("key", "", "key file")

var adminAddr = flag.String("admin", "", "admin addr")
var bShowVersion = flag.Bool("version", false, "show version")

func handleClient(conn net.Conn) {
	g_Conn2ClientInfo[conn] = &ClientInfo{conn: conn, clientMap: make(map[net.Conn]*Session), id2Session: make(map[string]*Session), isServer: false, quit: make(chan bool), responseTime: time.Now().Unix()}
	log.Println("client linked success", conn.RemoteAddr().String())
	g_Conn2ClientInfo[conn].loop()
	common.Read(conn, handleResponse)
	client, bHave := g_Conn2ClientInfo[conn]
	if bHave {
		close(client.quit)
		if client.isServer {
			for conn, session := range client.clientMap {
				conn.Close()
				common.RmId(client.serverName, session.id)
			}
			delete(g_ServerName2Conn, client.serverName)
			log.Println("unregister serverName", client.serverName)
		} else {
			getServerInfoByConn(conn, func(server *ClientInfo) {
				id := server.delClient(conn)
				log.Println("send quit")
				common.Write(server.conn, id, "clientquit", "")
			}, func() {})
		}
		delete(g_Conn2ClientInfo, conn)
	}
	conn.Close()
	log.Println("client disconnected", conn.RemoteAddr().String())
}

type cmdHandler func(args []string) (result string, bSuccess bool)

var g_AdminCommands map[string]cmdHandler

func addAdminCmd(cmd string, callback cmdHandler) {
	g_AdminCommands[cmd] = callback
}

func initAdminPort() {
	g_AdminCommands = make(map[string]cmdHandler)
	addAdminCmd("servers", _adminGetServers)
	addAdminCmd("sessions", _adminGetSession)
	addAdminCmd("kicksession", _adminKickSession)
	addAdminCmd("kickserver", _adminKickServer)
}

func _adminKickServer(args []string) (result string, bSuccess bool) {
	if len(args) < 1 {
		result = "please spec serverName"
		bSuccess = false
		return
	}
	conn, bHave := g_ServerName2Conn[args[0]]
	if bHave {
		common.Write(conn, "0", "showandquit", "admin kick you out")
		result = "kick server ok"
	} else {
		bSuccess = false
		result = "donnot have this serverName"
		return
	}
	bSuccess = true
	return
}

func _adminGetServers(args []string) (result string, bSuccess bool) {
	for _, server := range g_Conn2ClientInfo {
		if server.isServer {
			result += server.serverName + "\n"
		}
	}
	bSuccess = true
	return
}

func _adminKickSession(args []string) (result string, bSuccess bool) {
	if len(args) < 2 {
		result = "please spec serverName and session id"
		bSuccess = false
		return
	}
	conn, bHave := g_ServerName2Conn[args[0]]
	if bHave {
		server, bHave2 := g_Conn2ClientInfo[conn]
		if bHave2 {
			session, bHave := server.id2Session[args[1]]
			if bHave {
				if session.clientA != conn {
					common.Write(session.clientA, "0", "showandquit", "admin kick you out")
				} else if session.clientB != conn {
					common.Write(session.clientB, "0", "showandquit", "admin kick you out")
				}
				result = "kick session ok"
			} else {
				result = "no need kick"
			}
		} else {
			bSuccess = false
			result = "donnot have this conn"
		}
	} else {
		bSuccess = false
		result = "donnot have this serverName"
		return
	}
	bSuccess = true
	return
}

func _adminGetSession(args []string) (result string, bSuccess bool) {
	if len(args) < 1 {
		result = "please spec serverName"
		bSuccess = false
		return
	}
	conn, bHave := g_ServerName2Conn[args[0]]
	if bHave {
		server, bHave2 := g_Conn2ClientInfo[conn]
		if bHave2 {
			for _, session := range server.id2Session {
				result += session.String() + "\n"
			}
		} else {
			bSuccess = false
			result = "donnot have this conn"
		}
	} else {
		bSuccess = false
		result = "donnot have this serverName"
		return
	}
	bSuccess = true
	return
}

func processAdminCommand(command string) (result string, bSuccess bool) {
	arr := strings.Split(command, " ")
	cmd := arr[0]
	args := []string{}
	result = ""
	bSuccess = true
	for i := 1; i < len(arr); i++ {
		if strings.Trim(arr[i], " ") != "" {
			args = append(args, arr[i])
		}
	}
	callback, bHave := g_AdminCommands[cmd]
	if bHave {
		result, bSuccess = callback(args)
	} else {
		result = "unknown command:" + cmd
		maybe := ""
		for k := range g_AdminCommands {
			if strings.Index(k, command) >= 0 {
				maybe += k + "\n"
			}
		}
		if maybe != "" {
			result += ",maybe:\n" + maybe
		}
		bSuccess = false
	}
	return
}

func handleAdmin(conn net.Conn) {
	g_Conn2Admin[conn] = &AdminInfo{conn: conn}
	scanner := bufio.NewScanner(conn)
	//scanner.Split(split)
	for scanner.Scan() {
		command := scanner.Text()
		res, bSuccess := processAdminCommand(command)
		if bSuccess {
			res = "+" + res
		} else {
			res = "-" + res
		}
		res += "\n"
		l := len(res)
		conn.Write([]byte(strconv.Itoa(l) + "\n" + res))
	}
	delete(g_Conn2Admin, conn)
	conn.Close()
}

func handleResponse(conn net.Conn, id string, action string, content string) {
	//log.Println("got", id, action, content)
	getClientInfoByConn(conn, func(client *ClientInfo) {
		client.responseTime = time.Now().Unix()
	}, func() {
	})
	switch action {
	case "init":
		clientInfoStr := content
		var clientInfo common.ClientSetting
		err := json.Unmarshal([]byte(clientInfoStr), &clientInfo)
		if err != nil {
			log.Println("error decode clientinfo, kick out", conn.RemoteAddr().String())
			common.Write(conn, "0", "showandquit", "server decode clientInfo error")
			return
		}
		if common.Version != clientInfo.Version {
			s_version := fmt.Sprintf("%.2f", common.Version)
			c_version := fmt.Sprintf("%.2f", clientInfo.Version)
			log.Println("version not eq", conn.RemoteAddr().String(), s_version, c_version)
			common.Write(conn, "0", "showandquit", "client version:"+c_version+" not eq with server:"+s_version)
			return
		}
		serverName := clientInfo.Name
		if clientInfo.ClientType == "reg" {
			getClientInfoByName(serverName, func(server *ClientInfo) {
				common.Write(conn, "0", "showandquit", "already have the serverName!")
			}, func() {
				g_ServerName2Conn[serverName] = conn
				getClientInfoByConn(conn, func(info *ClientInfo) {
					info.serverName = serverName
					info.isServer = true
					info.id2MakeSession = make(map[string]*UDPMakeSession)
				}, func() {})
				common.Write(conn, "0", "show", "register service ok!")
			})
		} else if clientInfo.ClientType == "link" {
			if clientInfo.Mode < 0 || clientInfo.Mode > 2 {
				clientInfo.Mode = 0
			}
			serverName := clientInfo.Name
			getClientInfoByConn(conn, func(client *ClientInfo) {
				client.serverName = serverName
			}, func() {
			})
			getClientInfoByName(serverName, func(server *ClientInfo) {
				server.addClient(conn, clientInfo)
			}, func() {
				common.Write(conn, "0", "showandquit", "donnt have this service name")
			})
		}
	case "tunnel_error":
		getServerInfoByConn(conn, func(server *ClientInfo) {
			log.Println("<<=====tunnel_error", server.serverName, conn.RemoteAddr().String())
			session, bHave := server.id2Session[id]
			if bHave {
				session.status = "fail"
				common.Write(session.clientA, "0", "showandquit", content)
				server.delClient(session.clientA)
			}
		}, func() {
		})
	case "makeholefail":
		getServerInfoByConn(conn, func(server *ClientInfo) {
			udpsession, bHave := server.id2MakeSession[id]
			if bHave {
				log.Println("<<=====make hole fail", conn.RemoteAddr().String(), udpsession.serverName, udpsession.sessionId)
				sessionId := udpsession.sessionId
				session, _bHave := server.id2Session[sessionId]
				if _bHave {
					session.status = "fail"
					if session.method == "udp" {
						session.restartSession(server.serverName)
					} else if session.method == "restart" {
						if session.setting.Mode == 0 {
							tmp := session.clientA
							session.clientA = session.clientB
							session.clientB = tmp
							session.startCSMode()
						} else {
							server.delClient(session.clientB)
						}
					} else {
						server.delClient(session.clientA)
					}
				}
				delete(server.id2MakeSession, id)
			}
			common.RmId("makehole", id)
		}, func() {
		})
	case "makeholeok":
		getServerInfoByConn(conn, func(server *ClientInfo) {
			if content == "csmode" {
				session, _bHave := server.id2Session[id]
				if _bHave {
					log.Println("<<=====make hole ok", conn.RemoteAddr().String(), server.serverName, session.id)
					session.status = "ok"
				}
			}
			udpsession, bHave := server.id2MakeSession[id]
			if bHave {
				log.Println("<<=====make hole ok", conn.RemoteAddr().String(), udpsession.serverName, udpsession.sessionId)
				sessionId := udpsession.sessionId
				session, _bHave := server.id2Session[sessionId]
				if _bHave {
					session.status = "ok"
				}
				delete(server.id2MakeSession, id)
			}
			common.RmId("makehole", id)
		}, func() {
		})
	case "report_addrlist":
		getServerInfoByConn(conn, func(server *ClientInfo) {
			udpsession, bHave := server.id2MakeSession[id]
			//log.Println("test", udpsession, id, server.serverName)
			if bHave {
				log.Println("<<===report addr list ok", conn.RemoteAddr().String(), udpsession.serverName, udpsession.id)
				udpsession.beginMakeHole(1, content)
			}
		}, func() {
		})
	case "success_bust_a":
		getServerInfoByConn(conn, func(server *ClientInfo) {
			udpsession, bHave := server.id2MakeSession[id]
			if bHave {
				log.Println("<<=====success_bust_a", conn.RemoteAddr().String(), udpsession.serverName, udpsession.sessionId)
				udpsession.beginMakeHole(2, content)
			}
		}, func() {
		})
	// for c/s mode
	case "tunnel_close":
		getServerInfoByConn(conn, func(server *ClientInfo) {
			session := server.getSession(conn)
			if session != nil {
				common.Write(session.clientB, session.id+"-"+id, "csmode_s_tunnel_close", content)
			} else {
				println("no session")
			}
		}, func() {
		})
	case "tunnel_open":
		getServerInfoByConn(conn, func(server *ClientInfo) {
			session := server.getSession(conn)
			if session != nil {
				common.Write(session.clientB, session.id+"-"+id, "csmode_s_tunnel_open", content)
			} else {
				println("no session")
			}
		}, func() {
		})
	case "tunnel_msg_c":
		getServerInfoByConn(conn, func(server *ClientInfo) {
			session := server.getSession(conn)
			if session != nil {
				common.Write(session.clientB, session.id+"-"+id, "csmode_msg_c", content)
			} else {
				println("no session")
			}
		}, func() {
		})
	case "tunnel_msg_s":
		getServerInfoByConn(conn, func(server *ClientInfo) {
			arr := strings.Split(id, "-")
			clientId := arr[0]
			session, bHave := server.id2Session[clientId]
			if bHave {
				common.Write(session.clientA, id, "csmode_msg_s", content)
			} else {
				println("no session")
			}
		}, func() {
		})
	}
}

var err error
var g_Master net.Listener

func main() {
	flag.Parse()
	if *bShowVersion {
		fmt.Printf("%.2f\n", common.Version)
		return
	}
	g_Conn2ClientInfo = make(map[net.Conn]*ClientInfo)
	g_ServerName2Conn = make(map[string]net.Conn)
	g_Conn2Admin = make(map[net.Conn]*AdminInfo)
	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Println("cannot listen addr:" + err.Error())
		return
	}
	if *bUseSSL {
		config := &tls.Config{}
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0], err = tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Println("load key file error", err.Error())
			return
		}
		g_Master = tls.NewListener(listener, config)
	} else {
		g_Master = listener
	}
	go func() {
		for {
			conn, err := g_Master.Accept()
			if err != nil {
				continue
			}
			go handleClient(conn)
		}
	}()
	log.Println("master start success")
	if *adminAddr != "" {
		adminListener, err := net.Listen("tcp", *adminAddr)
		if err != nil {
			log.Println("cannot listen admin addr:" + err.Error())
			return
		}
		initAdminPort()
		go func() {
			for {
				conn, err := adminListener.Accept()
				if err != nil {
					continue
				}
				go handleAdmin(conn)
			}
		}()
		log.Println("admin service start success")
	}
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	<-c
	log.Println("received signal,shutdown")
	shutdown()
}

func shutdown() {
	for conn, client := range g_Conn2ClientInfo {
		if !client.isServer {
			log.Println("shutdown client", client.serverName)
			common.Write(conn, "0", "showandquit", "server shutdown")
		}
	}
}
