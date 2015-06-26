package pipe

import (
	"../common"
	"../ikcp"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"time"
)

const WriteBufferSize = 5000 //udp writer will add some data for checksum or encrypt
const ReadBufferSize = 7000  //so reader must be larger

const dataLimit = 4000

const mainV = 0
const subV = 1

type cache struct {
	b []byte
	l int
	c chan int
}

func init() {
}

type Action struct {
	t    string
	args []interface{}
}

func iclock() int32 {
	return int32((time.Now().UnixNano() / 1000000) & 0xffffffff)
}

func udp_output(buf []byte, _len int32, kcp *ikcp.Ikcpcb, user interface{}) int32 {
	c := user.(*UDPMakeSession)
	//log.Println("send udp", _len, c.remote.String())
	c.sock.WriteTo(buf[:_len], c.remote)
	return 0
}

const (
	Reset     byte = 0
	FirstSYN  byte = 6
	FirstACK  byte = 1
	SndSYN    byte = 2
	SndACK    byte = 3
	Data      byte = 4
	Ping      byte = 5
	Close     byte = 7
	CloseBack byte = 8
	ResetAck  byte = 9
)

func makeEncode(buf []byte, status byte, arg int) []byte {
	buf[0] = status
	binary.LittleEndian.PutUint32(buf[1:], uint32(arg))
	return buf
}

func makeDecode(data []byte) (status byte, arg int32) {
	if len(data) < 5 {
		return Reset, 0
	}
	status = data[0]
	arg = int32(binary.LittleEndian.Uint32(data[1:]))
	return
}

type UDPMakeSession struct {
	id                int
	idstr             string
	status            string
	overTime          int64
	quitChan          chan bool
	closeChan         chan bool
	recvChan          chan cache
	handShakeChan     chan string
	handShakeChanQuit chan bool
	sock              *net.UDPConn
	remote            *net.UDPAddr
	kcp               *ikcp.Ikcpcb
	do                chan Action
	do2               chan Action
	checkCanWrite     chan (chan bool)
	listener          *Listener
	closed            bool

	readBuffer    []byte
	processBuffer []byte
	encodeBuffer  []byte
	timeout       int64
	disBind       bool
}

type Listener struct {
	connChan   chan *UDPMakeSession
	quitChan   chan bool
	sock       *net.UDPConn
	readBuffer []byte
	sessions   map[string]*UDPMakeSession
}

func (l *Listener) Accept() (net.Conn, error) {
	var c *UDPMakeSession
	var err error
	select {
	case c = <-l.connChan:
	case <-l.quitChan:
	}
	if c == nil {
		err = errors.New("listener quit")
	}
	return net.Conn(c), err
}

func (l *Listener) Dump() {
	for addr, session := range l.sessions {
		log.Println("listener", addr, session.status)
	}
}

func (l *Listener) inner_loop() {
	sock := l.sock
	for {
		n, from, err := sock.ReadFromUDP(l.readBuffer)
		if err == nil {
			//log.Println("recv", n, from)
			addr := from.String()
			session, bHave := l.sessions[addr]
			if bHave {
				if session.status == "ok" {
					if session.remote.String() == from.String() && n >= int(ikcp.IKCP_OVERHEAD) {
						buf := make([]byte, n)
						copy(buf, l.readBuffer[:n])
						session.DoAction2("input", buf, n)
					}
					continue
				} else {
					session.serverDo(string(l.readBuffer[:n]))
				}
			} else {
				status, _ := makeDecode(l.readBuffer[:n])
				if status != FirstSYN {
					go sock.WriteToUDP([]byte("0"), from)
					log.Println("invalid package,reset", from, status)
					continue
				}
				sessionId := common.GetId("udp")
				session = &UDPMakeSession{status: "init", overTime: time.Now().Unix() + 10, remote: from, sock: sock, recvChan: make(chan cache), quitChan: make(chan bool), readBuffer: make([]byte, ReadBufferSize), processBuffer: make([]byte, ReadBufferSize), timeout: 30, do: make(chan Action), do2: make(chan Action), id: sessionId, handShakeChan: make(chan string), handShakeChanQuit: make(chan bool), listener: l, closeChan: make(chan bool), encodeBuffer: make([]byte, 5), checkCanWrite: make(chan (chan bool))}
				l.sessions[addr] = session
				session.serverInit(l)
				session.serverDo(string(l.readBuffer[:n]))
			}
			//log.Println("debug out.........")
		} else {
			e, ok := err.(net.Error)
			if !ok || !e.Timeout() {
				log.Println("recv error", err.Error(), from)
				l.remove(from.String())
				//time.Sleep(time.Second)
				break
			}
		}
	}
}

func (l *Listener) remove(addr string) {
	log.Println("listener remove", addr)
	session, bHave := l.sessions[addr]
	if bHave {
		common.RmId("udp", session.id)
	}
	delete(l.sessions, addr)
}

func (l *Listener) Close() error {
	if l.sock != nil {
		l.sock.Close()
		l.sock = nil
	} else {
		return nil
	}
	close(l.quitChan)
	return nil
}

func (l *Listener) Addr() net.Addr {
	return nil
}

func (l *Listener) loop() {
	l.inner_loop()
}

func Listen(addr string) (*Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	sock, _err := net.ListenUDP("udp", udpAddr)
	if _err != nil {
		return nil, _err
	}

	listener := &Listener{connChan: make(chan *UDPMakeSession), quitChan: make(chan bool), sock: sock, readBuffer: make([]byte, ReadBufferSize), sessions: make(map[string]*UDPMakeSession)}
	go listener.loop()
	return listener, nil
}

func Dial(addr string) (*UDPMakeSession, error) {
	return DialTimeout(addr, 30)
}

func DialTimeout(addr string, timeout int) (*UDPMakeSession, error) {
	bReset := false
	if timeout < 5 {
		bReset = true
		timeout = 5
	} else if timeout > 255 {
		bReset = true
		timeout = 255
	}
	if bReset {
		log.Println("timeout should in [5, 255], force reset timeout to", timeout)
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	sock, _err := net.ListenUDP("udp", &net.UDPAddr{})
	if _err != nil {
		log.Println("dial addr fail", _err.Error())
		return nil, _err
	}
	session := &UDPMakeSession{readBuffer: make([]byte, ReadBufferSize), do: make(chan Action), do2: make(chan Action), quitChan: make(chan bool), recvChan: make(chan cache), processBuffer: make([]byte, ReadBufferSize), closeChan: make(chan bool), encodeBuffer: make([]byte, 5), checkCanWrite: make(chan (chan bool))}
	session.remote = udpAddr
	session.sock = sock
	session.status = "firstsyn"
	session.timeout = int64(timeout)
	_timeout := int(timeout / 2)
	if _timeout < 5 {
		timeout = 5
	}
	arg := int(int32(timeout) + int32(mainV<<24) + int32(subV<<16))
	info := makeEncode(session.encodeBuffer, FirstSYN, arg)
	code := session.doAndWait(func() {
		sock.WriteToUDP(info, udpAddr)
	}, _timeout, func(status byte, arg int32) int {
		if status == ResetAck {
			_mainV, _subV := int(byte(arg>>24)), int(byte(arg>>16))
			log.Printf("pipe version not eq,%d.%d=>%d.%d", mainV, subV, _mainV, _subV)
			return 1
		}
		if status != FirstACK {
			return -1
		} else {
			session.status = "firstack"
			session.id = int(arg)
			return 0
		}
	})
	if code != 0 {
		return nil, errors.New("handshake fail,1")
	}
	code = session.doAndWait(func() {
		sock.WriteToUDP(makeEncode(session.encodeBuffer, SndSYN, session.id), udpAddr)
	}, _timeout, func(status byte, arg int32) int {
		if status != SndACK {
			return -1
		} else if session.id != int(arg) {
			return 2
		} else {
			session.status = "ok"
			return 0
		}
	})
	if code != 0 {
		return nil, errors.New("handshake fail,2")
	}
	session.kcp = ikcp.Ikcp_create(uint32(session.id), session)
	session.kcp.Output = udp_output
	ikcp.Ikcp_wndsize(session.kcp, 128, 128)
	ikcp.Ikcp_nodelay(session.kcp, 1, 10, 2, 1)
	go session.loop()
	return session, nil
}

func (session *UDPMakeSession) GetSock() *net.UDPConn {
	return session.sock
}
func (session *UDPMakeSession) doAndWait(f func(), sec int, readf func(status byte, arg int32) int) (code int) {
	t := time.NewTicker(50 * time.Millisecond)
	currT := time.Now().Unix()
	f()
out:
	for {
		select {
		case <-session.quitChan:
			break out
		case <-t.C:
			if time.Now().Unix()-currT >= int64(sec) {
				code = -1
				break out
			}
			session.sock.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, from, err := session.sock.ReadFromUDP(session.readBuffer)
			if err != nil {
				e, ok := err.(net.Error)
				if !ok || !e.Timeout() {
					log.Println("recv error", err.Error(), from)
					code = -2
					break out
				}
			} else {
				code = readf(makeDecode(session.readBuffer[:n]))
				if code >= 0 {
					break out
				}
			}
			go f()
		}
	}
	t.Stop()
	if code > 0 {
		log.Println("handshake fail,got code", code)
	}
	return
}

func (session *UDPMakeSession) serverDo(s string) {
	go func() {
		//log.Println("prepare handshake", session.remote)
		select {
		case <-session.handShakeChanQuit:
		case session.handShakeChan <- s:
		}
	}()
}
func (session *UDPMakeSession) serverInit(l *Listener) {
	go func() {
		c := time.NewTicker(50 * time.Millisecond)
		defer func() {
			close(session.handShakeChanQuit)
			c.Stop()
			if session.status != "ok" {
				session.Close()
			}
		}()
		overTime := time.Now().Unix() + session.timeout
	out:
		for {
			select {
			case s := <-session.handShakeChan:
				//log.Println("process handshake", session.remote)
				status, arg := makeDecode([]byte(s))
				switch session.status {
				case "init":
					if status != FirstSYN {
						session.sock.WriteToUDP(makeEncode(session.encodeBuffer, Reset, 0), session.remote)
						return
					}
					_mainV, _subV := int(byte(arg>>24)), int(byte(arg>>16))
					if _mainV != mainV || _subV != subV {
						session.sock.WriteToUDP(makeEncode(session.encodeBuffer, ResetAck, (mainV<<24)+(subV<<16)), session.remote)
						log.Printf("pipe version not eq,kickout,%d.%d=>%d.%d", mainV, subV, _mainV, _subV)
						return
					}
					session.status = "firstack"
					session.timeout = int64(arg & 0xff)
					session.sock.WriteToUDP(makeEncode(session.encodeBuffer, FirstACK, session.id), session.remote)
					overTime = time.Now().Unix() + session.timeout
				case "firstack":
					if status != SndSYN {
						return
					}
					session.status = "ok"
					session.kcp = ikcp.Ikcp_create(uint32(session.id), session)
					session.kcp.Output = udp_output
					ikcp.Ikcp_wndsize(session.kcp, 128, 128)
					ikcp.Ikcp_nodelay(session.kcp, 1, 10, 2, 1)
					go session.loop()
					go func() {
						select {
						case l.connChan <- session:
						case <-l.quitChan:
						}
					}()
					session.sock.WriteToUDP(makeEncode(session.encodeBuffer, SndACK, session.id), session.remote)
					overTime = time.Now().Unix() + session.timeout
				}
			case <-session.quitChan:
				break out
			case <-c.C:
				if time.Now().Unix() > overTime {
					return
				}
				switch session.status {
				case "firstack":
					session.sock.WriteToUDP(makeEncode(session.encodeBuffer, FirstACK, session.id), session.remote)
				case "ok":
					buf := make([]byte, 5)
					session.sock.WriteToUDP(makeEncode(buf, SndACK, session.id), session.remote)
				}
			}
		}
	}()
}

func (session *UDPMakeSession) loop() {
	curr := time.Now().Unix()
	session.overTime = curr + session.timeout
	ping := make(chan bool)
	pingC := 0
	callUpdate := false
	updateC := make(chan bool)
	if session.listener == nil {
		go func() {
			tmp := session.readBuffer
			t := time.Time{}
			session.sock.SetReadDeadline(t)
			for {
				n, from, err := session.sock.ReadFromUDP(tmp)
				if err != nil {
					e, ok := err.(net.Error)
					if !ok || !e.Timeout() {
						break
					}
					if session.disBind && ok && e.Timeout() {
						log.Println("force timeout!!!")
						session.sock.SetReadDeadline(time.Time{})
						break
					}
				}
				if session.remote.String() == from.String() {
					if n >= int(ikcp.IKCP_OVERHEAD) || n <= 5 {
						buf := make([]byte, n)
						copy(buf, session.readBuffer[:n])
						session.DoAction2("input", buf, n)
					}
				}
			}
		}()
	}
	updateF := func(n time.Duration) {
		if !callUpdate {
			callUpdate = true
			time.AfterFunc(n*time.Millisecond, func() {
				select {
				case updateC <- true:
				case <-session.quitChan:
				}
			})
		}
	}

	fastCheck := false
	waitList := [](chan bool){}
	recoverChan := make(chan bool)

	var waitRecvCache *cache
	go func() {
	out:
		for {
			select {
			//session.wait.Done()
			case <-ping:
				updateF(50)
				pingC++
				if pingC >= 4 {
					pingC = 0
					if ikcp.Ikcp_waitsnd(session.kcp) <= dataLimit/2 {
						go session.DoWrite(makeEncode(session.encodeBuffer, Ping, 0))
					}
				}
				if time.Now().Unix() > session.overTime {
					log.Println("overtime close", session.LocalAddr().String(), session.RemoteAddr().String())
					go session.Close()
				} else {
					time.AfterFunc(300*time.Millisecond, func() {
						select {
						case ping <- true:
						case <-session.quitChan:
						}
					})
				}
			case <-recoverChan:
				fastCheck = false
				for _, r := range waitList {
					log.Println("recover writing data")
					select {
					case r <- true:
					case <-session.quitChan:
					}
				}
				waitList = [](chan bool){}
			case c := <-session.checkCanWrite:
				if ikcp.Ikcp_waitsnd(session.kcp) > dataLimit {
					log.Println("wait for data limit")
					waitList = append(waitList, c)
					if !fastCheck {
						fastCheck = true
						var f func()
						f = func() {
							n := ikcp.Ikcp_waitsnd(session.kcp)
							//log.Println("fast check!", n, len(waitList))
							if n <= dataLimit/2 {
								select {
								case <-session.quitChan:
								case recoverChan <- true:
								}
							} else {
								updateF(20)
								time.AfterFunc(40*time.Millisecond, f)
							}
						}
						time.AfterFunc(20*time.Millisecond, f)
					}
				} else {
					select {
					case c <- true:
					case <-session.quitChan:
					}
				}
			case ca := <-session.recvChan:
				tmp := session.processBuffer
				for {
					hr := ikcp.Ikcp_recv(session.kcp, tmp, ReadBufferSize)
					if hr > 0 {
						status := tmp[0]
						if status == Data {
							copy(ca.b, tmp[1:hr])
							ca.c <- int(hr - 1)
							break
						} else {
							session.DoAction("recv", status)
						}
					} else {
						waitRecvCache = &ca
						break
					}
				}
			case action := <-session.do2:
				switch action.t {
				case "input":
					session.overTime = time.Now().Unix() + session.timeout
					args := action.args
					s := args[0].([]byte)
					n := args[1].(int)
					if n < 5 {
						log.Println("recv reset")
						go session._Close(false)
						break
					} else if n == 5 {
						status, _ := makeDecode(s)
						if status == Reset || status == ResetAck {
							log.Println("recv reset2", status)
							go session._Close(false)
						}
						break
					}
					ikcp.Ikcp_input(session.kcp, s, n)
					if waitRecvCache != nil {
						ca := *waitRecvCache
						tmp := session.processBuffer
						for {
							hr := ikcp.Ikcp_recv(session.kcp, tmp, ReadBufferSize)
							if hr > 0 {
								status := tmp[0]
								if status == Data {
									waitRecvCache = nil
									copy(ca.b, tmp[1:hr])
									ca.c <- int(hr - 1)
									break
								} else {
									session.DoAction("recv", status)
								}
							} else {
								break
							}
						}
					}
					updateF(10)
				case "write":
					b := action.args[0].([]byte)
					ikcp.Ikcp_send(session.kcp, b, len(b))
					updateF(10)
				}
			case <-session.quitChan:
				break out
			case <-updateC:
				now := uint32(iclock())
				ikcp.Ikcp_update(session.kcp, now)
				callUpdate = false
			}
		}
	}()
	select {
	case ping <- true:
	case <-session.quitChan:
	}
out:
	for {
		select {
		case <-session.quitChan:
			if session.disBind {
				break out
			}
		case action := <-session.do:
			switch action.t {
			case "quit":
				if session.closed {
					break
				}
				session._Close(true)
			case "closebegin":
				//A tell B to close and wait
				time.AfterFunc(time.Millisecond*500, func() {
					//log.Println("close over, step3", session.LocalAddr().String(), session.RemoteAddr().String())
					go session.DoAction("closeover")
				})
				buf := make([]byte, 5)
				go session.DoWrite(makeEncode(buf, Close, 0))
			case "closeover":
				//A call timeover
				close(session.closeChan)
				break out
			case "closeend":
				//B call close
				session._Close(false)
				break out
			case "recv":
				status := (action.args[0]).(byte)
				switch status {
				case CloseBack:
					//A call from B
					//log.Println("recv back close, step2", session.LocalAddr().String(), session.RemoteAddr().String())
					go session.DoAction("closeover")
				case Close:
					if session.closed {
						break
					}
					if session.status != "ok" {
						session._Close(false)
					} else {
						//log.Println("recv remote close, step1", session.LocalAddr().String(), session.RemoteAddr().String())
						buf := make([]byte, 5)
						go session.DoWrite(makeEncode(buf, CloseBack, 0))
						time.AfterFunc(time.Millisecond*500, func() {
							//log.Println("close remote over, step4", session.LocalAddr().String(), session.RemoteAddr().String())
							if session.closed {
								return
							}
							go session.DoAction("closeend")
						})
					}
				case Reset:
					log.Println("recv reset")
					go session._Close(false)
				case Ping:
				default:
					if session.status != "ok" {
						session.Close()
					}
				}
			}
		}
	}
}

func (session *UDPMakeSession) _Close(bFirstCall bool) {
	if session.closed {
		return
	}
	session.closed = true
	//session.wait.Wait()
	go func() {
		//log.Println("pipe begin close", session.LocalAddr().String(), session.RemoteAddr().String())
		if bFirstCall {
			go session.DoAction("closebegin", session.LocalAddr().String())
			<-session.closeChan
		} else {
			close(session.closeChan)
		}
		//log.Println("pipe end close", session.id)
		close(session.quitChan)
		if session.listener != nil {
			session.listener.remove(session.remote.String())
		} else {
			if session.sock != nil && !session.disBind {
				session.sock.Close()
			}
		}
	}()
}

func (session *UDPMakeSession) DisBind() error {
	log.Println("dis bind !!!!")
	if session.disBind {
		return nil
	}
	session.disBind = true
	if session.listener == nil {
		session.sock.SetReadDeadline(time.Now())
	}
	if session.closed {
		return nil
	}
	close(session.quitChan)
	if session.listener != nil {
		//session.sock.Close()
		session.listener.remove(session.remote.String())
	}
	return nil
}
func (session *UDPMakeSession) Close() error {
	if session.closed {
		return nil
	}
	if session.status != "ok" {
		session._Close(false)
		return nil
	}
	go session.DoAction("quit")
	<-session.closeChan
	return nil
}

func (session *UDPMakeSession) DoAction2(action string, args ...interface{}) {
	//session.wait.Add(1)
	//log.Println(action, len(args))
	select {
	case session.do2 <- Action{t: action, args: args}:
	case <-session.quitChan:
		//session.wait.Done()
	}
}
func (session *UDPMakeSession) DoAction(action string, args ...interface{}) {
	//session.wait.Add(1)
	//log.Println(action, len(args))
	select {
	case session.do <- Action{t: action, args: args}:
	case <-session.quitChan:
		//session.wait.Done()
	}
}

func (session *UDPMakeSession) processInput(s string, n int) {
}

func (session *UDPMakeSession) LocalAddr() net.Addr {
	return session.sock.LocalAddr()
}

func (session *UDPMakeSession) RemoteAddr() net.Addr {
	return net.Addr(session.remote)
}

func (session *UDPMakeSession) SetDeadline(t time.Time) error {
	return session.sock.SetDeadline(t)
}

func (session *UDPMakeSession) SetReadDeadline(t time.Time) error {
	return session.sock.SetReadDeadline(t)
}

func (session *UDPMakeSession) SetWriteDeadline(t time.Time) error {
	return session.sock.SetWriteDeadline(t)
}

func (session *UDPMakeSession) DoWrite(s []byte) bool {
	wc := make(chan bool)
	select {
	case session.checkCanWrite <- wc:
		select {
		case <-wc:
		case <-session.quitChan:
			return false
		}
		session.DoAction2("write", s)
		return true
	case <-session.quitChan:
		return false
	}
}

func (session *UDPMakeSession) Write(b []byte) (n int, err error) {
	sendL := len(b)
	if sendL == 0 || session.status != "ok" {
		return 0, nil
	}
	data := make([]byte, sendL+1)
	data[0] = Data
	copy(data[1:], b)
	ok := session.DoWrite(data)
	if !ok {
		return 0, errors.New("closed")
	}
	return sendL, err
}

//udp read does not relay on the len(p), please make a big enough array to cache data
func (session *UDPMakeSession) Read(p []byte) (n int, err error) {
	wc := cache{p, 0, make(chan int)}
	select {
	case session.recvChan <- wc:
		select {
		case n = <-wc.c:
		case <-session.quitChan:
			n = -1
		}
	case <-session.quitChan:
		n = -1
	}
	if n == -1 {
		log.Println("force quit for read error", session.remote.String())
		return 0, errors.New("force quit for read error")
	} else {
		return n, nil
	}
}
