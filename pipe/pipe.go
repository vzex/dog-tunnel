package pipe

import (
        "../ikcp"
        "bufio"
        "io/ioutil"
        "net"
        "fmt"
        "error"
)

const WriteBufferSize = 5000 //udp writer will add some data for checksum or encrypt
const ReadBufferSize = 7000  //so reader must be larger

func init() {
}

type UDPMakeSession struct {
	id             int
	idstr          string
	status         string
	overTime       int64
	recvChan       chan string
	recvChan2      chan string
	sendChan       chan string
	timeChan       chan int64
	quitChan       chan bool
	sock           *net.UDPConn
	remote         *net.UDPAddr
	send           string
	kcp            *ikcp.Ikcpcb
	action         string

	readBuffer    []byte
	processBuffer []byte
	timeout       int64
}

type Listener struct {
        connChan chan net.Conn
        quitChan chan bool
        sock *net.UDPConn
        readBuffer []byte
        sessions map[string]*UDPMakeSession
}

func (l *Listener) Accept() (c net.Conn, err error) {
        c <- l.connChan
        if c == nil {
                err = errors.New("listener quit")
        }
        return
}

func (l *Listener) inner_loop() {
        sock := l.sock
        for {
                sock.SetReadDeadline(time.Now().Add(2 * time.Second))
                n, from, err := sock.ReadFromUDP(l.readBuffer)
                if err == nil {
                        //log.Println("recv", string(tempBuff[:10]), from)
                        addr := from.String()
                        session, bHave := l.sessions[addr]
                        if bHave {
                                if session.status == "ok" {
                                        if session.remote.String() == from.String() {
                                                //log.Println("input msg", n)
                                                ikcp.Ikcp_input(session.kcp, tempBuff[:n], n)
                                                session.processInput()
                                        }
                                        continue
                                }
                        } else {
                                session = &UDPMakeSession{status: "init", overTime: time.Now().Unix() + 10, remote: from, send: "", sock: sock, recvChan: make(chan string), closed: false, sendChan: make(chan string), timeChan: make(chan int64), quitChan: make(chan bool), recvChan2: make(chan string), readBuffer: make([]byte, readBufferSize), processBuffer: make([]byte, readBufferSize), timeout: 100}
                                l.sessions[addr] = session
                                go session.loop()
                        }
                        arr := strings.Split(common.Xor(string(l.readBuffer[:n])), "@")
                        switch session.status {
                        case "init":
                                if len(arr) > 1 {
                                        if arr[0] == "1snd" {
                                                session.idstr = arr[1]
                                                session.id, _ = strconv.Atoi(session.idstr)
                                                if len(arr) > 2 {
                                                        session.action = arr[2]
                                                } else {
                                                        session.action = "socks5"
                                                }
                                                if len(arr) > 3 {
                                                        tail := arr[3]
                                                        if tail != "" {
                                                                log.Println("got encrpyt key", tail)
                                                                aesKey := "asd4" + tail
                                                                aesBlock, _ := aes.NewCipher([]byte(aesKey))
                                                                session.SetCrypt(getEncodeFunc(aesBlock), getDecodeFunc(aesBlock))
                                                        }
                                                }
                                                session.SetStatusAndSend("1ack", "1ack@"+session.idstr)
                                        }
                                } else {
                                        if len(arr[0]) > 10 {
                                                log.Println("status invalid", session.status, arr[0][:10])
                                                session.SetStatusAndSend(session.status, "reset")
                                        } else {
                                                log.Println("status invalid", session.status, arr[0])
                                                session.SetStatusAndSend(session.status, "reset")
                                        }
                                }
                        case "1ack":
                                if len(arr) > 1 {
                                        if arr[0] == "2snd" && arr[1] == session.idstr {
                                                session.SetStatusAndSend("ok", "2ack@"+session.idstr)
                                        }
                                } else {
                                        log.Println("status invalid", session.status, arr[0][:10])
                                        session.SetStatusAndSend(session.status, "reset")
                                }
                        }
                        //log.Println("debug out.........")
                } else if !err.(net.Error).Timeout() {
                        fmt.Println("recv error", err.Error(), from)
                        //time.Sleep(time.Second)
                        sock.Close()
                        break out
                }
                if bForceQuit {
                        break out
                }
        }
}

func (l *Listener) Close() error {
        defer func() {
                recover()
        }()
        l.quitChan <- true
        return nil
}

func (l *Listener) loop() {
        go l.inner_loop()
        out:
        for {
                select {
                case <- l.quitChan:
                        close(l.quitChan)
                        close(l.sock)
                        break out
                }
        }
}

func Listen(addr string) *Listener{
        udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Println("resolve addr fail", err.Error())
		return nil
	}
	sock, _err := net.ListenUDP("udp", udpAddr)
	if _err != nil {
		fmt.Println("listen addr fail", _err.Error())
		return nil
	}

        listener := &Listener{quitChan:make(chan bool), connChan:make(chan net.Conn), sock: sock, readBuffer:make([]byte, ReadBufferSize), sessions:make(map[string]*UDPMakeSession)}
        go listener.loop()
        return listener
}


func Dial(addr string) *UDPMakeSession {
        session := &UDPMakeSession {quitChan:make(chan bool)}
        go session.loop()
        return session
}

func (session *UDPMakeSession) loop() {
        out:
        for {
                select {
                case <- session.quitChan:
                        session._Close()
                        break out
                }
        }
}

func (session *UDPMakeSession) _Close() {
        close(session.sock)
        close(session.quitChan)
        session.sock = nil
}

func (session *UDPMakeSession) Close() {
	defer func() {
		recover()
        }()
        session.quitChan <- true
}

func (session *UDPMakeSession) processInput() {
	for {
		tmp := session.processBuffer
		hr := ikcp.Ikcp_recv(session.kcp, tmp, readBufferSize)
		//println("loop", hr)
		if hr > 0 {
			if session.decode != nil {
				d := session.decode(tmp[:hr])
				hr = int32(len(d))
				copy(tmp, d)
			}
			//log.Println("try recv", hr)
			if !session.closed && hr > 0 {
				s := string(tmp[:hr])
				go func() { session.recvChan2 <- s }()
			}
			//log.Println("try recved", hr)
		} else {
			break
		}
	}
}

func (session *UDPMakeSession) Dial(addr string) string {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Println("resolve addr fail", err.Error())
		session.Close()
		return "fail"
	}
	addrS := udpAddr.String()
	sock, _err := net.ListenUDP("udp", &net.UDPAddr{})
	if _err != nil {
		fmt.Println("dial addr fail", err.Error())
		session.Close()
		return "fail"
	}
	if session.id == 0 {
		session.id = rand.Intn(1000000) + int(time.Now().Unix()%10000)
	}
	session.idstr = fmt.Sprintf("%d", session.id)
	log.Println("session id", session.id, sock.LocalAddr().String())
	encrypt_tail := ""
	if *bEncrypt {
		encrypt_tail = string([]byte(fmt.Sprintf("%d%d", int32(time.Now().Unix()), (rand.Intn(100000) + 100)))[:12])
		aesKey := "asd4" + encrypt_tail
		log.Println("debug aeskey", encrypt_tail)
		aesBlock, _ := aes.NewCipher([]byte(aesKey))
		session.SetCrypt(getEncodeFunc(aesBlock), getDecodeFunc(aesBlock))
	}
	session.SetStatusAndSend("1snd", "1snd@"+session.idstr+"@"+*remoteAction+"@"+encrypt_tail)
	session.remote = udpAddr
	session.sock = sock
	session.ClientCheck()
	return session.status
}
func (session *UDPMakeSession) LocalAddr() net.Addr {
	return session.sock.LocalAddr()
}

func (session *UDPMakeSession) RemoteAddr() net.Addr {
	return session.sock.RemoteAddr()
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

func (session *UDPMakeSession) Write(b []byte) (n int, err error) {
	if session.encode != nil {
		b = session.encode(b)
	}
	sendL := len(b)
	if sendL == 0 || session.status != "ok" {
		return 0, nil
	}
	debug("try write", sendL, session.id)
	session.sendChan <- string(b[:sendL])
	debug("try write2", sendL, session.id)
	//ikcp.Ikcp_send(session.kcp, b[:sendL], sendL)
	return sendL, nil
}

func (session *UDPMakeSession) Read(p []byte) (n int, err error) {
	if clientType == 0 {
		b := []byte(<-session.recvChan)
		l := len(b)
		copy(p, b[:l])
		//log.Println("real recv", l, string(b[:l]))
		if l == 0 {
			return 0, errors.New("force quit for read error")
		} else {
			go func() { session.timeChan <- time.Now().Unix() + session.timeout }()
			session.send = ""
			return l, nil
		}
	} else {
		tmp := session.readBuffer
		for {
			hr := ikcp.Ikcp_recv(session.kcp, tmp, readBufferSize)
			if hr > 0 {
				if session.decode != nil {
					d := session.decode(tmp[:hr])
					copy(p, d)
					hr = int32(len(d))
				} else {
					copy(p, tmp[:hr])
				}
				go func() { session.timeChan <- time.Now().Unix() + session.timeout }()
				session.send = ""
				//log.Println("real recv client", hr, string(p))
				return int(hr), nil
			}
			bHave := false
			//log.Println("want read0-------------!", hr)
			for {
				session.sock.SetReadDeadline(time.Now().Add(time.Second * 2))
				n, addr, err := session.sock.ReadFromUDP(tmp)
				//log.Println("want read!", n, addr, err)
				// Generic non-address related errors.
				if addr == nil && err != nil && !err.(net.Error).Timeout() {
					log.Println("error!", err.Error())
					return 0, err
				}
				debug("redirect", n)
				if n == 5 && common.Xor(string(tmp[:n])) == "reset" {
					return 0, errors.New("force reset")
				}
				ikcp.Ikcp_input(session.kcp, tmp[:n], n)
				bHave = true
				break
			}
			if !bHave {
				time.Sleep(10 * time.Millisecond)
			}

		}
	}
}

