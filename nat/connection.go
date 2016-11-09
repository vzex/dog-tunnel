package nat

import "../ikcp"

import (
	"errors"
	"flag"
	"log"
	"net"
	"time"
)

const (
	Ping byte = 1
	Data byte = 2
)

var bDebug = flag.Bool("debug", false, "whether show nat pipe debug msg")

var defaultQueueSize = 1

const dataLimit = 4000

func debug(args ...interface{}) {
	if *bDebug {
		log.Println(args...)
	}
}
func iclock() int32 {
	return int32((time.Now().UnixNano() / 1000000) & 0xffffffff)
}

func udp_output(buf []byte, _len int32, kcp *ikcp.Ikcpcb, user interface{}) int32 {
	debug("write!!!", _len)
	c := user.(*Conn)
	c.conn.WriteTo(buf[:_len], c.remote)
	return 0
}

type cache struct {
	b []byte
	l int
	c chan int
}

type Conn struct {
	conn          *net.UDPConn
	local, remote net.Addr
	closed        bool
	quit          chan bool
	sendChan      chan string
	checkCanWrite chan chan bool
	readChan      chan cache
	kcp           *ikcp.Ikcpcb

	tmp            []byte
	tmp2           []byte
	encode, decode func([]byte) []byte
	overTime       int64
}

func newConn(sock *net.UDPConn, local, remote net.Addr, id int) *Conn {
	sock.SetDeadline(time.Time{})
	conn := &Conn{conn: sock, local: local, remote: remote, closed: false, quit: make(chan bool), tmp: make([]byte, 2000), tmp2: make([]byte, 2000), sendChan: make(chan string, 10), checkCanWrite: make(chan chan bool), readChan: make(chan cache), overTime: time.Now().Unix() + 30}
	debug("create", id)
	conn.kcp = ikcp.Ikcp_create(uint32(id), conn)
	conn.kcp.Output = udp_output
	ikcp.Ikcp_wndsize(conn.kcp, 128, 128)
	ikcp.Ikcp_nodelay(conn.kcp, 1, 10, 2, 1)
	return conn
}

func (c *Conn) Run() {
	go c.onUpdate()
}

func (c *Conn) onUpdate() {
	recvChan := make(chan []byte)
	go func() {
		for {
			n, addr, err := c.conn.ReadFrom(c.tmp)
			//debug("want read!", n, addr, err)
			// Generic non-address related errors.
			if addr == nil && err != nil {
				if err.(net.Error).Timeout() {
					continue
				} else {
					break
				}
			}
			b := make([]byte, n)
			copy(b, c.tmp[:n])
			select {
			case recvChan <- b:
			case <-c.quit:
				return
			}
		}
	}()
	ping := make(chan struct{})
	pingC := 0

	updateChan := time.NewTicker(20 * time.Millisecond)
	waitList := [](chan bool){}
	recoverChan := make(chan bool)
	var waitRecvCache *cache
	go func() {
		select {
		case ping <- struct{}{}:
		case <-c.quit:
		}

	}()
out:
	for {
		select {
		case <-ping:
			pingC++
			if pingC >= 4 {
				pingC = 0
				go c.Ping()
			}
			if time.Now().Unix() > c.overTime {
				log.Println("overtime close", c.LocalAddr().String(), c.RemoteAddr().String())
				go c.Close()
			} else {
				time.AfterFunc(300*time.Millisecond, func() {
					select {
					case ping <- struct{}{}:
					case <-c.quit:
					}
				})
			}
		case cache := <-c.readChan:
			for {
				hr := ikcp.Ikcp_recv(c.kcp, c.tmp2, 2000)
				if hr > 0 {
					action := c.tmp2[0]
					if action == Data {
						copy(cache.b, c.tmp2[1:hr])
						hr--
						if c.decode != nil {
							d := c.decode(cache.b[:hr])
							copy(cache.b, d)
							hr = int32(len(d))
						}
						select {
						case cache.c <- int(hr):
						case <-c.quit:
						}
					} else {
						continue
					}
				} else {
					waitRecvCache = &cache
				}
				break
			}
		case b := <-recvChan:
			c.overTime = time.Now().Unix() + 30
			ikcp.Ikcp_input(c.kcp, b, len(b))
			if waitRecvCache != nil {
				ca := *waitRecvCache
				for {
					hr := ikcp.Ikcp_recv(c.kcp, c.tmp2, 2000)
					if hr > 0 {
						action := c.tmp2[0]
						if action == Data {
							waitRecvCache = nil
							copy(ca.b, c.tmp2[1:hr])
							hr--
							if c.decode != nil {
								d := c.decode(ca.b[:hr])
								copy(ca.b, d)
								hr = int32(len(d))
							}
							select {
							case ca.c <- int(hr):
							case <-c.quit:
							}
						} else {
							continue
						}
					} else {
					}
					break
				}
			}
		case <-recoverChan:
			for _, r := range waitList {
				log.Println("recover writing data")
				select {
				case r <- true:
				case <-c.quit:
				}
			}
			waitList = [](chan bool){}
		case s := <-c.checkCanWrite:
			if !c.closed {
				if ikcp.Ikcp_waitsnd(c.kcp) > dataLimit {
					log.Println("wait for data limit")
					waitList = append(waitList, s)
					var f func()
					f = func() {
						n := ikcp.Ikcp_waitsnd(c.kcp)
						if n <= dataLimit/2 {
							select {
							case <-c.quit:
								log.Println("recover writing data quit")
							case recoverChan <- true:
							}
						} else {
							time.AfterFunc(40*time.Millisecond, f)
						}
					}
					time.AfterFunc(20*time.Millisecond, f)
					log.Println("wait for data limitover")
				} else {
					select {
					case s <- true:
					case <-c.quit:
					}
				}
			}
		case s := <-c.sendChan:
			b := []byte(s)
			ikcp.Ikcp_send(c.kcp, b, len(b))
		case <-updateChan.C:
			if c.closed {
				break out
			}
			ikcp.Ikcp_update(c.kcp, uint32(iclock()))
		case <-c.quit:
			break out
		}
	}
	updateChan.Stop()
}
func (c *Conn) Read(b []byte) (int, error) {
	if !c.closed {
		var n = 0
		wc := cache{b, 0, make(chan int)}
		select {
		case c.readChan <- wc:
			select {
			case n = <-wc.c:
			case <-c.quit:
				n = 0
			}
		case <-c.quit:
			n = 0
		}
		return n, nil
	}
	return 0, errors.New("force quit")
}

// type 0, check, 1 msg
func (c *Conn) Write(b []byte) (int, error) {
	if c.closed {
		return 0, errors.New("eof")
	}

	if c.encode != nil {
		b = c.encode(b)
	}
	sendL := len(b)
	if sendL == 0 {
		return 0, nil
	}
	//log.Println("try write", sendL)
	wc := make(chan bool)
	select {
	case c.checkCanWrite <- wc:
		select {
		case <-wc:
			data := make([]byte, sendL+1)
			data[0] = Data
			copy(data[1:], b)
			c.sendChan <- string(data)
		case <-c.quit:
		}
	case <-c.quit:
	}
	return sendL, nil
}

func (c *Conn) Ping() (int, error) {
	if c.closed {
		return 0, errors.New("eof")
	}
	wc := make(chan bool)
	select {
	case c.checkCanWrite <- wc:
		select {
		case <-wc:
			data := []byte{Ping}
			c.sendChan <- string(data)
		case <-c.quit:
		}
	case <-c.quit:
	}
	return 1, nil
}
func (c *Conn) Close() error {
	if !c.closed {
		c.closed = true
	}
	if c.quit != nil {
		close(c.quit)
		c.quit = nil
	}
	return c.conn.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	return c.local
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.remote
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *Conn) SetCrypt(encode, decode func([]byte) []byte) {
	c.encode = encode
	c.decode = decode
}
