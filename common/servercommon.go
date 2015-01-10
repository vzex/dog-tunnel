package common

import (
	"fmt"
	"log"
	"net"
	"strconv"
	"time"
)

type ClientInfo struct {
	Conn       net.Conn
	ClientMap  map[net.Conn]*Session
	Id2Session map[string]*Session

	UserName  string
	ClientKey string

	ResponseTime int64

	Quit chan bool

	IsServer       bool
	ServerName     string // is serverName != "", this client is a server!
	Id2MakeSession map[string]*UDPMakeSession
}

type UDPMakeSession struct {
	Id         string
	CreateTime int64
	ClientA    net.Conn
	ClientB    net.Conn
	SessionId  string
	PipeType   string
	Status     string
	ServerName string
	Quit       chan bool
}

type Session struct {
	Id                string
	ClientA           net.Conn
	ClientB           net.Conn
	Status            string
	OverTime          int64
	Method            string
	Setting           ClientSetting
	MakeHoleResponseN int
	MakeHoleHasFail   bool
	Quit              chan bool
}

func (session *Session) String() string {
	return fmt.Sprintf("%s|delay:%d|status:%s|method:%s|ClientA:%s|ClientB:%s|Pipes:%d/%d", session.Id, session.Setting.Delay, session.Status, session.Method, session.ClientA.RemoteAddr().String(), session.ClientB.RemoteAddr().String(), session.MakeHoleResponseN, session.Setting.PipeNum)
}

type AdminInfo struct {
	Conn net.Conn
}

func (session *Session) RestartSession(ServerName string) {
	log.Println("restart session", session.Id)
	session.Method = "restart"
	session.Quit <- true
	tmp := session.ClientA
	session.ClientA = session.ClientB
	session.ClientB = tmp
	session.MakeHoleResponseN = 0
	session.MakeHoleHasFail = false
	n := session.Setting.PipeNum
	session.StartSession(n, ServerName, session.Id)
}

func (session *Session) Down() {
	if session.Quit != nil {
		close(session.Quit)
		session.Quit = nil
	}
	session.Status = "down"
}

func (session *Session) StartCSMode() {
	//make sure ClientA and ClientB not exchanged
	session.Method = "cs"
	clientConn := session.ClientA
	session.Status = "csmode_begin"
	Write(clientConn, session.Id, "csmode_c_begin", "")
	session.Loop()
}

func (session *Session) Loop() {
	go func() {
		checkChan := time.NewTicker(10 * time.Second)
	out:
		for {
			select {
			case <-checkChan.C:
				//println("check lop session status", session.status)
				if time.Now().Unix() > session.OverTime {
					if session.Status != "ok" {
						if session.Method == "udp" || session.Method == "cs" {
							session.ClientA.Close()
						} else {
							session.ClientB.Close()
						}
					}
				}
			case <-session.Quit:
				log.Println("session loop quit", session.Id)
				break out
			}
		}
		checkChan.Stop()
	}()
}

func (session *Session) StartSession(n int, ServerName, sessionId string) {
	if n > 10 {
		if session.Method == "udp" || session.Method == "cs" {
			Write(session.ClientA, "0", "showandquit", "pipen cannot larger than "+strconv.Itoa(10))
		} else {
			Write(session.ClientB, "0", "showandquit", "pipen cannot larger than "+strconv.Itoa(10))
		}
	}
	for i := 0; i < n; i++ {
		session.startUdpSession(ServerName, sessionId, "common")
	}
	//session.startUdpSession(ServerName, sessionId, "file")
	session.OverTime = time.Now().Add(60 * time.Second).Unix()
	session.Loop()
}

func (session *Session) startUdpSession(ServerName, sessionId, pipeType string) {
	udpSessionId := GetId("makehole")
	log.Println("start session", session.Id, session.Setting.Mode, ServerName, udpSessionId)
	udpSession := &UDPMakeSession{CreateTime: time.Now().Unix(), Id: udpSessionId, ClientA: session.ClientA, ClientB: session.ClientB, SessionId: sessionId, PipeType: pipeType, ServerName: ServerName, Status: "init", Quit: make(chan bool)}
	GetClientInfoByName(ServerName, func(server *ClientInfo) {
		server.Id2MakeSession[udpSession.Id] = udpSession
	}, func() {})
	udpSession.BeginMakeHole(0, "")
	udpSession.Loop()
}

func (s *ClientInfo) GetSession(conn net.Conn) *Session {
	session, bHave := s.ClientMap[conn]
	if bHave {
		return session
	} else {
		return nil
	}
}

func (s *ClientInfo) AddClient(conn net.Conn, clientInfo ClientSetting) {
	id := GetId(s.ServerName)
	s.ClientMap[conn] = &Session{ClientA: conn, ClientB: s.Conn, Method: "udp", OverTime: 0, Status: "init", Id: id, Setting: clientInfo, Quit: make(chan bool), MakeHoleResponseN: 0, MakeHoleHasFail: false}
	s.Id2Session[id] = s.ClientMap[conn]
	if s.ClientMap[conn].Setting.Mode == 2 {
		s.ClientMap[conn].StartCSMode()
	} else {
		if clientInfo.AesKey != "" {
			Write(s.Conn, id, "aeskey", clientInfo.AesKey)
		}
		n := clientInfo.PipeNum
		s.ClientMap[conn].StartSession(n, s.ServerName, id)
	}
}

func (s *ClientInfo) Loop() {
	go func() {
		checkChan := time.NewTicker(10 * time.Second)
	out:
		for {
			select {
			case <-checkChan.C:
				if time.Now().Unix()-s.ResponseTime > 1800 {
					log.Println("timeout,client loop quit", s.Conn.RemoteAddr().String())
					break out
				}
			case <-s.Quit:
				break out
			}
		}
		checkChan.Stop()
		s.Conn.Close()
	}()
}

func (s *ClientInfo) DelClient(conn net.Conn) string {
	session, bHave := s.ClientMap[conn]
	if bHave {
		Write(conn, "0", "showandquit", "server kick you out")
		id := session.Id
		session.Down()
		log.Println("remove client session", id)
		delete(s.Id2Session, id)
		delete(s.ClientMap, conn)
		RmId(s.ServerName, id)
		return id
	}
	return ""
}

func (udpsession *UDPMakeSession) Remove(bTimeout bool) {
	if bTimeout {
		log.Println("timeout,remove udpsession", udpsession.Id)
	} else {
		//log.Println("remove udpsession", udpsession.Id)
	}
	close(udpsession.Quit)
	GetClientInfoByName(udpsession.ServerName, func(server *ClientInfo) {
		delete(server.Id2MakeSession, udpsession.Id)
		session, bHave := server.Id2Session[udpsession.SessionId]
		if bHave && bTimeout {
			Write(session.ClientA, udpsession.Id, "remove_udpsession", "")
			Write(session.ClientB, udpsession.Id, "remove_udpsession", "")
		}
	}, func() {})
	RmId("makehole", udpsession.Id)
}

func (udpsession *UDPMakeSession) Loop() {
	go func() {
		checkChan := time.NewTicker(10 * time.Second)
	out:
		for {
			select {
			case <-checkChan.C:
				if time.Now().Unix()-udpsession.CreateTime > 120 {
					udpsession.Remove(true)
					break out
				}
			case <-udpsession.Quit:
				break out
			}
		}
		checkChan.Stop()
	}()
}

func (udpsession *UDPMakeSession) BeginMakeHole(step int, content string) {
	var session *Session = nil
	GetClientInfoByName(udpsession.ServerName, func(server *ClientInfo) {
		session = server.Id2Session[udpsession.SessionId]
	}, func() {})
	if session != nil && session.Method == "cs" {
		return
	}
	id := udpsession.Id
	ClientA := udpsession.ClientA
	ClientB := udpsession.ClientB
	if step == 0 {
		log.Println("===>>tell a to report addrlist", ClientA.RemoteAddr().String(), udpsession.ServerName, udpsession.Id)
		delay := 0
		if session != nil {
			delay = session.Setting.Delay
		}
		Write(ClientA, id+"-"+udpsession.SessionId+"-"+udpsession.PipeType, "query_addrlist_a", ClientA.RemoteAddr().(*net.TCPAddr).IP.String()+":"+strconv.Itoa(delay))
		if session != nil {
			session.Status = "tella"
		}
		udpsession.Status = "tella"
	} else if step == 1 {
		if udpsession.Status == "tella" {
			udpsession.Status = "atellb"
			if session != nil {
				session.Status = "atellb"
			}
			log.Println("===>>tell b to report addlist,give b the a's addrlist", ClientB.RemoteAddr().String(), udpsession.ServerName, udpsession.Id)
			Write(ClientB, id+"-"+udpsession.SessionId+"-"+udpsession.PipeType, "query_addrlist_b", ClientB.RemoteAddr().(*net.TCPAddr).IP.String()+":"+content)
		} else if udpsession.Status == "atellb" {
			udpsession.Status = "bust_start_a"
			if session != nil {
				session.Status = "bust_start_a"
			}
			log.Println("=====>>tell a the b 's addrlist, and a start bust", ClientA.RemoteAddr().String(), udpsession.ServerName, udpsession.Id)
			Write(ClientA, id, "tell_bust_a", content)
		}
	} else if step == 2 {
		udpsession.Status = "bust_start_b"
		if session != nil {
			session.Status = "bust_start_b"
		}
		log.Println("=====>>tell b start bust", ClientB.RemoteAddr().String(), udpsession.ServerName, udpsession.Id)
		Write(ClientB, id, "tell_bust_b", content)
	}
}

func GetServerInfoByConn(conn net.Conn, cb_ok func(*ClientInfo), cb_fail func()) {
	info, bHave := Conn2ClientInfo[conn]
	if bHave {
		if info.IsServer {
			cb_ok(info)
		} else {
			ServerName := info.ServerName
			GetClientInfoByName(ServerName, cb_ok, cb_fail)
		}
	} else {
		cb_fail()
	}
}
func GetClientInfoByConn(conn net.Conn, cb_ok func(*ClientInfo), cb_fail func()) {
	info, bHave := Conn2ClientInfo[conn]
	if bHave {
		cb_ok(info)
	} else {
		cb_fail()
	}
}
func GetClientInfoByName(ServerName string, cb_ok func(*ClientInfo), cb_fail func()) {
	conn, bHave := ServerName2Conn[ServerName]
	if bHave {
		GetClientInfoByConn(conn, cb_ok, cb_fail)
		return
	} else {
		cb_fail()
	}
}

func GetOnlineServiceNumByNameAndIP(userName, ip string) int {
	size := 0
	for _, info := range Conn2ClientInfo {
		if info.IsServer && info.UserName == userName && (ip == info.Conn.RemoteAddr().(*net.TCPAddr).IP.String()) {
			size++
		}
	}
	return size
}

func GetOnlineServiceNumByName(userName string) int {
	size := 0
	for _, info := range Conn2ClientInfo {
		if info.IsServer && info.UserName == userName {
			size++
		}
	}
	return size
}

var ServerName2Conn map[string]net.Conn
var Conn2ClientInfo map[net.Conn]*ClientInfo
var Conn2Admin map[net.Conn]*AdminInfo
