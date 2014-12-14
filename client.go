package main

import (
	"./common"
	"bufio"
        "errors"
	"crypto/aes"
	"crypto/cipher"
	_ "crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"./ikcp"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"os/user"
	"path"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var authKey = flag.String("auth", "", "key for auth")

var serviceAddr = flag.String("service", "", "listen addr for client connect")
var localAddr = flag.String("local", "", "if local not empty, treat me as client, this is the addr for local listen, otherwise, treat as server")
var remoteAction = flag.String("action", "socks5", "for client control server, if action is socks5,remote is socks5 server, if is addr like 127.0.0.1:22, remote server is a port redirect server")
var bVerbose = flag.Bool("v", false, "verbose mode")
var bShowVersion = flag.Bool("version", false, "show version")
var bLoadSettingFromFile = flag.Bool("f", false, "load setting from file(~/.dtunnel)")
var bEncrypt = flag.Bool("encrypt", false, "p2p mode encrypt")
var dnsCacheNum = flag.Int("dnscache", 0, "if > 0, dns will cache xx minutes")


var remoteConn net.Conn
var clientType = 1

type dnsInfo struct {
	Ip                  string
	overTime, cacheTime int64
}

func (u *dnsInfo) IsAlive() bool {
	return time.Now().Unix() < u.overTime
}

func (u *dnsInfo) SetCacheTime(t int64) {
	if t >= 0 {
		u.cacheTime = t
	} else {
		t = u.cacheTime
	}
	u.overTime = t + time.Now().Unix()
}
func (u *dnsInfo) DeInit() {}

var g_ClientMap map[string]*Client
var markName = ""
var bForceQuit = false

type UDPMakeSession struct {
	id int
	idstr string
	status string
	overTime int64
	quitcheck chan bool
	recvChan chan string
	sendChan chan string
	sock *net.UDPConn
	remote *net.UDPAddr
	send	string
	kcp *ikcp.Ikcpcb
        encode, decode func([]byte)[]byte
        closed bool
        action string
        authed bool
}
func iclock() int32 {
        return int32((time.Now().UnixNano()/1000000) & 0xffffffff)
}

func udp_output(buf []byte, _len int32, kcp *ikcp.Ikcpcb, user interface{}) int32 {
        //log.Println("send udp", _len)
        c := user.(*UDPMakeSession)
        c.sock.WriteTo(buf[:_len], c.remote)
        return 0
}

var tempBuff []byte
var g_MakeSession map[string]*UDPMakeSession
func ServerCheck(sock *net.UDPConn) {
	println("begin check")
	func() {
		out:
		for {
			//sock.SetReadDeadline(time.Now().Add(2*time.Second))
			n, from, err := sock.ReadFromUDP(tempBuff)
			if err == nil {
				//log.Println("recv", string(tempBuff[:20]), from)
				addr := from.String()
				session, bHave := g_MakeSession[addr]
				if bHave {
					if session.status == "ok" {
                                                if session.remote.String() == from.String() {
                                                        //log.Println("input msg", n)
                                                        ikcp.Ikcp_input(session.kcp, tempBuff[:n], n)
                                                        session.Process()
                                                }
						continue
					}
				} else {
                                        session = &UDPMakeSession{status:"init", overTime:time.Now().Unix() + 10, remote:from, send:"", quitcheck:make(chan bool), sock:sock, recvChan:make(chan string), closed:false, sendChan:make(chan string, 10)}
                                        if *authKey == "" {
                                                session.authed = true
                                        }
					g_MakeSession[addr]= session
					go session.ClientCheck()
				}
				arr:=strings.Split(string(tempBuff[:n]), "@")
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
                                                                        session.SetCrypt(func(s []byte) []byte {
                                                                                if aesBlock == nil {
                                                                                        return s
                                                                                } else {
                                                                                        padLen := aes.BlockSize - (len(s) % aes.BlockSize)
                                                                                        for i := 0; i < padLen; i++ {
                                                                                                s = append(s, byte(padLen))
                                                                                        }
                                                                                        srcLen := len(s)
                                                                                        encryptText := make([]byte, srcLen+aes.BlockSize)
                                                                                        iv := encryptText[srcLen:]
                                                                                        for i := 0; i < len(iv); i++ {
                                                                                                iv[i] = byte(i)
                                                                                        }
                                                                                        mode := cipher.NewCBCEncrypter(aesBlock, iv)
                                                                                        mode.CryptBlocks(encryptText[:srcLen], s)
                                                                                        return encryptText
                                                                                }
                                                                        }, func(s []byte) []byte {
                                                                                if aesBlock == nil {
                                                                                        return s
                                                                                } else {
                                                                                        if len(s) < aes.BlockSize*2 || len(s)%aes.BlockSize != 0 {
                                                                                                return []byte{}
                                                                                        }
                                                                                        srcLen := len(s) - aes.BlockSize
                                                                                        decryptText := make([]byte, srcLen)
                                                                                        iv := s[srcLen:]
                                                                                        mode := cipher.NewCBCDecrypter(aesBlock, iv)
                                                                                        mode.CryptBlocks(decryptText, s[:srcLen])
                                                                                        paddingLen := int(decryptText[srcLen-1])
                                                                                        if paddingLen > 16 {
                                                                                                return []byte{}
                                                                                        }
                                                                                        return decryptText[:srcLen-paddingLen]
                                                                                }
                                                                        })
                                                                }
                                                        }
                                                        session.SetStatusAndSend("1ack", "1ack@"+session.idstr)
						}
					} else {
						session.Close()
					}
					case "1ack":
					if len(arr) > 1 {
						if arr[0] == "2snd" && arr[1] == session.idstr {
							session.SetStatusAndSend("ok", "2ack@"+session.idstr)
						}
					} else {
						session.Close()
					}
				}
			} else {
				fmt.Println("recv error", err.Error(), from)
                                //time.Sleep(time.Second)
				sock.Close()
				break out
			}
			if bForceQuit {
				break out
			}
		}
	}()
}
func Listen(addr string) *net.UDPConn {
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
	fmt.Println("listen addr ok", udpAddr)
	return sock
}

func (session *UDPMakeSession) Auth() {
        if !session.authed && clientType == 1 {
                session.authed = true
                log.Println("request auth key")
                common.Write(net.Conn(session), "-1", "auth", *authKey)
        }
}

func (session *UDPMakeSession) CheckAuth(action, key string) bool {
        if !session.authed && clientType == 0 {
                if action == "auth" {
                        if key == *authKey {
                                session.authed = true
                                fmt.Println("auth key succeed")
                                return true
                        } else {
                                fmt.Println("auth key fail")
                                return false
                        }
                } else {
                        fmt.Println("auth key must send", action, key)
                        return false
                }
        } else {
                return true
        }
}

func (session *UDPMakeSession) Dial(addr string) string {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		fmt.Println("resolve addr fail", err.Error())
		return "fail"
	}
	//sock, _err := net.DialUDP("udp", nil, udpAddr)
	sock, _err := net.ListenUDP("udp", &net.UDPAddr{})
	if _err != nil {
		fmt.Println("dial addr fail", err.Error())
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
		session.SetCrypt(func(s []byte) []byte {
			if aesBlock == nil {
				return s
			} else {
				padLen := aes.BlockSize - (len(s) % aes.BlockSize)
				for i := 0; i < padLen; i++ {
					s = append(s, byte(padLen))
				}
				srcLen := len(s)
				encryptText := make([]byte, srcLen+aes.BlockSize)
				iv := encryptText[srcLen:]
				for i := 0; i < len(iv); i++ {
					iv[i] = byte(i)
				}
				mode := cipher.NewCBCEncrypter(aesBlock, iv)
				mode.CryptBlocks(encryptText[:srcLen], s)
				return encryptText
			}
		}, func(s []byte) []byte {
			if aesBlock == nil {
				return s
			} else {
				if len(s) < aes.BlockSize*2 || len(s)%aes.BlockSize != 0 {
					return []byte{}
				}
				srcLen := len(s) - aes.BlockSize
				decryptText := make([]byte, srcLen)
				iv := s[srcLen:]
				mode := cipher.NewCBCDecrypter(aesBlock, iv)
				mode.CryptBlocks(decryptText, s[:srcLen])
				paddingLen := int(decryptText[srcLen-1])
				if paddingLen > 16 {
					return []byte{}
				}
				return decryptText[:srcLen-paddingLen]
			}
		})
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

func (session *UDPMakeSession) SetCrypt(encode, decode func([]byte)[]byte) {
        session.encode = encode
        session.decode = decode
}
func (session *UDPMakeSession) Write(b []byte) (n int, err error) {
        if session.closed {
                return 0, errors.New("force quit")
        }
        if session.encode != nil {
                b = session.encode(b)
        }
        sendL := len(b)
        if sendL == 0 {return 0, nil}
        //log.Println("try write", sendL)
	session.sendChan <- string(b[:sendL])
        //log.Println("try write2", sendL)
        //ikcp.Ikcp_send(session.kcp, b[:sendL], sendL)
        return sendL, nil
}

func (session *UDPMakeSession) Read(p []byte) (n int, err error) {
        if session.closed {
                return 0, errors.New("force quit")
        }
        if clientType == 0 {
                b := []byte(<- session.recvChan)
                l := len(b)
                copy(p, b[:l])
                //log.Println("real recv", l, string(b[:l]))
                if l == 0 {
                        return 0, errors.New("force quit for read error")
                } else {
                        session.overTime = time.Now().Unix() + 10
                        session.send = ""
                        return l, nil
                }
        } else {
                tmp:=make([]byte, 2000)
                for {
                        if session.closed {
                                return 0, errors.New("force quit")
                        }
                        hr := ikcp.Ikcp_recv(session.kcp, tmp, 2000)
                        if hr > 0 {
                                copy(p, tmp[:hr])
                                if session.decode != nil {
                                        d:= session.decode(p[:hr])
                                        copy(p, d)
                                        hr = int32(len(d))
                                }
                                session.overTime = time.Now().Unix() + 10
                                session.send = ""
                                //log.Println("real recv client", hr)
                                return int(hr), nil
                        }
                        bHave := false
                        for {
                                n, addr, err := session.sock.ReadFrom(tmp)
                                //debug("want read!", n, addr, err)
                                // Generic non-address related errors.
                                if addr == nil && err != nil {
                                        log.Println("error!", err.Error())
                                        return 0, err
                                }
                                if session.closed {
                                        return 0, errors.New("force quit")
                                }
                                //debug("redirect", n)
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

func (session *UDPMakeSession) Process() {
        tmp := make([]byte, 2000)
        for {
                hr := ikcp.Ikcp_recv(session.kcp, tmp, 2000)
                //println("loop", hr)
                if hr > 0 {
                        if session.decode != nil {
                                d:= session.decode(tmp[:hr])
                                hr = int32(len(d))
                                copy(tmp, d)
                        }
                        //log.Println("try recv", hr)
                        if !session.closed && hr > 0 {
                                session.recvChan <- string(tmp[:hr])
                        }
                } else {
                        break
                }
        }
}

func (session *UDPMakeSession) ClientCheck() {
	go func() {
		t := time.Tick(20*time.Millisecond)
		out:
		for {
			select {
			case s:=<-session.sendChan:
				if !session.closed {
					b:=[]byte(s)
					ikcp.Ikcp_send(session.kcp, b, len(b))
				}
			case <-t:
                                //log.Println("-------", session.status, session.send,  time.Now().Unix() ,session.overTime )
                                if session.status == "ok" {
                                        ikcp.Ikcp_update(session.kcp, uint32(iclock()))
                                }
				if time.Now().Unix() > session.overTime {
                                        if session.status == "ok" && session.send != "" {
                                                session.send = ""
                                        } else {
                                                log.Println("remove over time udp", session.overTime, time.Now().Unix())
                                                session.Close()
                                        }
                                        break out
				} else {
					if session.send != "" {
						//log.Println("try send", session.send, session.remote)
						session.sock.WriteToUDP([]byte(session.send), session.remote)
					}
				}
			case <- session.quitcheck:
				break out
			}
		}
	}()

        if clientType == 0 {return}
	buf := make([]byte, 512)
	out:
	for {
		n, from, err := session.sock.ReadFromUDP(buf)
		if err == nil {
			log.Println("head recv", string(buf[:n]), from)
			arr:=strings.Split(string(buf[:n]), "@")
			switch session.status {
				case "1snd":
				if len(arr) > 1 {
					if arr[0] == "1ack" && arr[1] == session.idstr {
						session.SetStatusAndSend("2snd", "2snd@"+session.idstr)
					}
				} else {
					break out
				}
				case "2snd":
				if len(arr) > 1 {
					if arr[0] == "2ack" && arr[1] == session.idstr {
						session.SetStatusAndSend("ok", "")
						break out
					}
				} else {
					break out
				}
			}
		} else {
			break out
		}
	}
}
func (session *UDPMakeSession) Close () error {
        if session.closed {return nil}
        if clientType == 1 {
                session.sock.Close()
        }
        addr := session.remote.String()
        if clientType == 1 {
                log.Println("remove udp pipe", session.sock.LocalAddr().String())
        } else {
                log.Println("remove udp pipe", addr)
        }
	close(session.quitcheck)
        if session.recvChan != nil {
                close(session.recvChan)
        }
        if session.sendChan!= nil {
                close(session.sendChan)
        }
        olds, have := g_MakeSession[addr]
        if have && olds == session {
                delete(g_MakeSession, addr)
        }
        session.closed = true
        return nil
}
func (session *UDPMakeSession) SetStatusAndSend(status, content string) {
	session.status = status
	session.overTime = time.Now().Unix() + 10
	session.send = content
	log.Println("set status", status, content, session.overTime)
	if status == "ok" && session.kcp == nil {
		session.kcp = ikcp.Ikcp_create(uint32(session.id), session)
		session.kcp.Output = udp_output
                if content != "" {
                        session.overTime -= 5
                } else {
                        session.overTime += 5
                }
		ikcp.Ikcp_wndsize(session.kcp, 128, 128)
		ikcp.Ikcp_nodelay(session.kcp, 1, 10, 2, 1)

                client, have := g_ClientMap[session.idstr]
		log.Println("add udp session", session.id, session.remote, have)
                if !have {
                        client = &Client{id: session.idstr, ready: true, bUdp: true, sessions: make(map[string]*clientSession), specPipes: make(map[string]net.Conn), pipes: make(map[int]net.Conn)}
                        g_ClientMap[session.idstr] = client
                }
                client.action = session.action
                client.pipes[0] = net.Conn(session)
                go client.Run(0, "")
                log.Println("add common session", session.id)
                if clientType == 1 && !have {
                        client.MultiListen()
                }
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

func main() {
        rand.Seed(time.Now().Unix())
	flag.Parse()
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
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		n := 0
		for {
			<-c
			log.Println("received signal,shutdown")
			bForceQuit = true
			n++
			if n > 5 {
				log.Println("force shutdown")
				os.Exit(-1)
			}
		}
	}()

	loop := func() bool {
		if bForceQuit {
			return true
		}
                g_ClientMap = make(map[string]*Client)
                g_MakeSession= make(map[string]*UDPMakeSession)
                tempBuff = make([]byte, 2000)
		if clientType == 0 {
			sock := Listen(*serviceAddr)
			if sock!=nil {
				ServerCheck(sock)
			}
		} else {
			session := &UDPMakeSession{status:"init", overTime:time.Now().Unix() + 10, send:"", quitcheck:make(chan bool), sendChan:make(chan string, 10)}
                        if *authKey == "" {
                                session.authed = true
                        }
			session.Dial(*serviceAddr)
		}
		if bForceQuit {
			return true
		}
		return false
	}
	//if clientType == 0 {
		for {
			if loop() {
				break
			}
			time.Sleep(10 * time.Second)
		}
	//} else {
	//	loop()
	//}
	log.Println("service shutdown")
}

type clientSession struct {
	pipe      net.Conn
	localConn net.Conn
	status    string
	recvMsg   string
	extra     uint8
}

func (session *clientSession) processSockProxy(sc *Client, sessionId, content string, callback func()) {
	pipe := session.pipe
	session.recvMsg += content
	bytes := []byte(session.recvMsg)
	size := len(bytes)
	//log.Println("recv msg-====", len(session.recvMsg),  session.recvMsg, session.status, sessionId)
	switch session.status {
	case "init":
		if session.localConn != nil {
			session.localConn.Close()
			session.localConn = nil
		}
		if size < 2 {
			//println("wait init")
			return
		}
		var _, nmethod uint8 = bytes[0], bytes[1]
		//println("version", version, nmethod)
		session.status = "version"
		session.recvMsg = string(bytes[2:])
		session.extra = nmethod
	case "version":
		if uint8(size) < session.extra {
			//println("wait version")
			return
		}
		var send = []uint8{5, 0}
		go common.Write(pipe, sessionId, "tunnel_msg_s", string(send))
		session.status = "hello"
		session.recvMsg = string(bytes[session.extra:])
		session.extra = 0
		//log.Println("now", len(session.recvMsg))
	case "hello":
		var hello reqMsg
		bOk, tail := hello.read(bytes)
		if bOk {
			go func() {
				var ansmsg ansMsg
				url := hello.url
				needcache := false
				usecache := false
				if *dnsCacheNum > 0 && hello.atyp == 3 {
					host := string(hello.dst_addr[1 : 1+hello.dst_addr[0]])
					cache := common.GetCacheContainer("dns")
					cacheInfo := cache.GetCache(host)
					if cacheInfo == nil {
						needcache = true
					} else {
						url = cacheInfo.(*dnsInfo).Ip + fmt.Sprintf(":%d", hello.dst_port2)
						cacheInfo.SetCacheTime(-1)
						usecache = true
					}
				}
				for {
					s_conn, err := net.DialTimeout(hello.reqtype, url, 30*time.Second)
					if err != nil {
						if usecache {
							host := string(hello.dst_addr[1 : 1+hello.dst_addr[0]])
							cache := common.GetCacheContainer("dns")
							cache.DelCache(host)
							url = hello.url
							usecache = false
							continue
						}
						log.Println("connect to local server fail:", err.Error())
						//msg := "cannot connect to bind addr" + *localAddr
						ansmsg.gen(&hello, 4)
						go common.Write(pipe, sessionId, "tunnel_msg_s", string(ansmsg.buf[:ansmsg.mlen]))
						//common.Write(pipe, sessionId, "tunnel_error", msg)
						return
					} else {
						if needcache {
							cache := common.GetCacheContainer("dns")
							host := string(hello.dst_addr[1 : 1+hello.dst_addr[0]])
							cache.AddCache(host, &dnsInfo{Ip: strings.Split(s_conn.RemoteAddr().String(), ":")[0]}, int64(*dnsCacheNum*60))
							log.Println("add host", host, "to dns cache")
						}
						session.localConn = s_conn
						go handleLocalPortResponse(sc, sessionId)
						ansmsg.gen(&hello, 0)
						go common.Write(pipe, sessionId, "tunnel_msg_s", string(ansmsg.buf[:ansmsg.mlen]))
						session.status = "ok"
						session.recvMsg = string(tail)
						callback()
						return
					}
				}
			}()
		} else {
			//log.Println("wait hello")
		}
		return
	case "ok":
		return
	}
	session.processSockProxy(sc, sessionId, "", callback)
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
		msg.url = string(msg.dst_addr[1 : 1+msg.dst_addr[0]])
		msg.url += fmt.Sprintf(":%d", msg.dst_port2)
	case 4: //ipv6
		msg.url = fmt.Sprintf("%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%x%x:%d", msg.dst_addr[0], msg.dst_addr[1], msg.dst_addr[2], msg.dst_addr[3],
			msg.dst_addr[4], msg.dst_addr[5], msg.dst_addr[6], msg.dst_addr[7],
			msg.dst_addr[8], msg.dst_addr[9], msg.dst_addr[10], msg.dst_addr[11],
			msg.dst_addr[12], msg.dst_addr[13], msg.dst_addr[14], msg.dst_addr[15],
			msg.dst_port2)
	}
	log.Println(msg.reqtype, msg.url, msg.atyp, msg.dst_port2)
	return true, buf[2:]
}

type Client struct {
	id        string
	buster    bool
	pipes     map[int]net.Conn          // client for pipes
	specPipes map[string]net.Conn       // client for pipes
	sessions  map[string]*clientSession // session to pipeid
	ready     bool
	bUdp      bool
        action    string
}

// pipe : client to client
// local : client to local apps
func (sc *Client) getSession(sessionId string) *clientSession {
	session, _ := sc.sessions[sessionId]
	return session
}

func (sc *Client) removeSession(sessionId string) bool {
	if clientType == 1 {
		common.RmId("udp", sessionId)
	}
	session, bHave := sc.sessions[sessionId]
	if bHave {
		if session.localConn != nil {
			session.localConn.Close()
		}
		delete(sc.sessions, sessionId)
		log.Println("client", sc.id, "remove session", sessionId)
		return true
	}
	return false
}

func (sc *Client) OnTunnelRecv(pipe net.Conn, sessionId string, action string, content string) {
	//println("recv p2p tunnel", sessionId, action, content)
	session := sc.getSession(sessionId)
	var conn net.Conn
	if session != nil {
		conn = session.localConn
	}
        if !pipe.(*UDPMakeSession).CheckAuth(action, content) {
                common.Write(pipe, sessionId, "authfail", "")
                return
        }
	switch action {
        case "authfail":
                bForceQuit = true
                fmt.Println("auth key not eq")
                sc.Quit()
                if g_LocalConn!=nil {
                        g_LocalConn.Close()
                }
	case "tunnel_error":
		if conn != nil {
			conn.Write([]byte(content))
			log.Println("tunnel error", content, sessionId)
		}
		sc.removeSession(sessionId)
		//case "serve_begin":
	case "tunnel_msg_s":
		if conn != nil {
			//println("tunnel msg", sessionId, len(content))
			conn.Write([]byte(content))
		} else {
			log.Println("cannot tunnel msg", sessionId)
		}
	case "tunnel_close_s":
		sc.removeSession(sessionId)
	case "ping", "pingback":
		//log.Println("out recv", action)
		if action == "ping" {
			common.Write(pipe, sessionId, "pingback", "")
		}
	case "tunnel_msg_c":
		if conn != nil {
			//log.Println("tunnel", (content), sessionId)
			conn.Write([]byte(content))
		} else if sc.action == "socks5" {
			if session == nil {
				return
			}
			session.processSockProxy(sc, sessionId, content, func() {
				sc.OnTunnelRecv(pipe, sessionId, action, session.recvMsg)
			})
		}
	case "tunnel_close":
		sc.removeSession(sessionId)
	case "tunnel_open":
		if clientType == 0 {
			if sc.action != "socks5" {
				s_conn, err := net.DialTimeout("tcp", sc.action, 10*time.Second)
				if err != nil {
					log.Println("connect to local server fail:", err.Error())
					msg := "cannot connect to bind addr" + sc.action
					common.Write(pipe, sessionId, "tunnel_error", msg)
					//remoteConn.Close()
					return
				} else {
					sc.sessions[sessionId] = &clientSession{pipe: pipe, localConn: s_conn}
					go handleLocalPortResponse(sc, sessionId)
				}
			} else {
				sc.sessions[sessionId] = &clientSession{pipe: pipe, localConn: nil, status: "init", recvMsg: ""}
			}
		}
	}
}

func (sc *Client) Quit() {
	log.Println("client quit", sc.id)
	delete(g_ClientMap, sc.id)
	for id, _ := range sc.sessions {
		sc.removeSession(id)
	}
	for id, pipe := range sc.pipes {
                pipe.Close()
                delete(sc.pipes, id)
	}
}

///////////////////////multi pipe support
var g_LocalConn net.Listener

func (sc *Client) MultiListen() bool {
	if g_LocalConn == nil {
                var err error
		g_LocalConn, err = net.Listen("tcp", *localAddr)
		if err != nil {
			log.Println("cannot listen addr:" + err.Error())
			if remoteConn != nil {
				remoteConn.Close()
			}
			return false
		}
		println("service start success,please connect", *localAddr, "p2p mode")
		func() {
			quit := false
			ping := time.Tick(time.Second * 5)
                        for _, pipe := range sc.pipes {
                                pipe.(*UDPMakeSession).Auth()
                                common.Write(pipe, "-1", "ping", "")
                        }
			go func() {
			out:
				for {
					select {
					case <-ping:
						if quit {
							break out
						}
						//log.Println("test ping !")
                                                empty := true
						for n, pipe := range sc.pipes {
                                                        empty = false
                                                        pipe.(*UDPMakeSession).Auth()

                                                        e := common.Write(pipe, "-1", "ping", "")
                                                        if e != nil {
                                                                fmt.Println("write error in ping:", e.Error())
                                                                pipe.Close()
                                                                delete(sc.pipes, n)
                                                                if len(sc.pipes) == 0 {
                                                                        empty = true
                                                                }
                                                        }
						}
                                                if empty {
                                                        id, _ := strconv.Atoi(sc.id)
                                                        log.Println("recreate pipe for client", id)
                                                        session := &UDPMakeSession{status:"init", overTime:time.Now().Unix() + 10, send:"", quitcheck:make(chan bool), id:id, sendChan:make(chan string, 10)}
                                                        if *authKey == "" {
                                                                session.authed = true
                                                        }
                                                        session.Dial(*serviceAddr)
                                                }
					}
				}
			}()
			for {
				conn, err := g_LocalConn.Accept()
				if err != nil {
                                        if bForceQuit {
                                                break
                                        } else {
                                                continue
                                        }
				}
				sessionId := common.GetId("udp")
				pipe := sc.getOnePipe()
				if pipe == nil {
					log.Println("cannot get pipe for client, wait for recover...")
                                        time.Sleep(time.Second)
                                        continue
				}
				sc.sessions[sessionId] = &clientSession{pipe: pipe, localConn: conn}
				log.Println("client", sc.id, "create session", sessionId)
				go handleLocalServerResponse(sc, sessionId)
			}
			quit = true
		}()
	}
	return true
}

func (sc *Client) getOnePipe() net.Conn {
	tmp := []int{}
	for id, _ := range sc.pipes {
		tmp = append(tmp, id)
	}
	size := len(tmp)
	if size == 0 {
		return nil
	}
	index := rand.Intn(size)
	log.Println("choose pipe for ", sc.id, ",", index, "of", size)
	hitId := tmp[index]
	pipe, _ := sc.pipes[hitId]
	return pipe
}

///////////////////////multi pipe support

func (sc *Client) Run(index int, specPipe string) {
	var pipe net.Conn
	if index >= 0 {
		pipe = sc.pipes[index]
	} else {
		pipe = sc.specPipes[specPipe]
	}
	if pipe == nil {
		return
	}
	go func() {
		callback := func(conn net.Conn, sessionId, action, content string) {
			if sc != nil {
				sc.OnTunnelRecv(conn, sessionId, action, content)
			}
		}
		log.Println("client begin read", index)
		common.Read(pipe, callback)
		log.Println("client end read", index)
                if clientType == 0 {
                        sc.Quit()
                        return
                }
		if index >= 0 {
                        _newpipe, have := sc.pipes[index]
                        if have && _newpipe == pipe {
                                pipe.Close()
                                log.Println("client remove udp pipe", index)
                                delete(sc.pipes, index)
                        } else {
                                log.Println("client dont remove the newcreated udp pipe", index)
                        }
		}
        }()
}

func (sc *Client) LocalAddr() net.Addr                { return nil }
func (sc *Client) Close() error                       { return nil }
func (sc *Client) RemoteAddr() net.Addr               { return nil }
func (sc *Client) SetDeadline(t time.Time) error      { return nil }
func (sc *Client) SetReadDeadline(t time.Time) error  { return nil }
func (sc *Client) SetWriteDeadline(t time.Time) error { return nil }

func handleLocalPortResponse(client *Client, id string) {
	sessionId := id
	if !client.bUdp {
		arr := strings.Split(id, "-")
		sessionId = arr[1]
	}
	session := client.getSession(sessionId)
	if session == nil {
		return
	}
	conn := session.localConn
	if conn == nil {
		return
	}
	arr := make([]byte, 1000)
	reader := bufio.NewReader(conn)
	for {
		size, err := reader.Read(arr)
		if err != nil {
			break
		}
		if common.Write(session.pipe, id, "tunnel_msg_s", string(arr[0:size])) != nil {
			break
		}
	}
	// log.Println("handlerlocal down")
	if client.removeSession(sessionId) {
		common.Write(session.pipe, id, "tunnel_close_s", "")
	}
}

func handleLocalServerResponse(client *Client, sessionId string) {
	session := client.getSession(sessionId)
	if session == nil {
		return
	}
	pipe := session.pipe
	if pipe == nil {
		return
	}
	conn := session.localConn
        pipe.(*UDPMakeSession).Auth()
	common.Write(pipe, sessionId, "tunnel_open", "")
	arr := make([]byte, 1000)
	reader := bufio.NewReader(conn)
	for {
		size, err := reader.Read(arr)
		if err != nil {
			break
		}
		if common.Write(pipe, sessionId, "tunnel_msg_c", string(arr[0:size])) != nil {
			break
		}
	}
	common.Write(pipe, sessionId, "tunnel_close", "")
	client.removeSession(sessionId)
}
