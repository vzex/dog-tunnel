package nat

import "../ikcp"

import (
	"../pipe"
	"errors"
	"flag"
	"log"
	"net"
	"time"
)

const (
	normalMsg = byte(iota)
	confirmMsg
	pingMsg
)

var bDebug = flag.Bool("debug", false, "whether show nat pipe debug msg")

var defaultQueueSize = 1

func debug(args ...interface{}) {
	if *bDebug {
		log.Println(args...)
	}
}
func iclock() int32 {
	return int32((time.Now().UnixNano() / 1000000) & 0xffffffff)
}

func udp_output(buf []byte, _len int32, kcp *ikcp.Ikcpcb, user interface{}) int32 {
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
	recvChan      chan cache
	kcp           *ikcp.Ikcpcb

	tmp            []byte
	encode, decode func([]byte) []byte
}

func newConn(sock *net.UDPConn, local, remote net.Addr, id int) *Conn {
	sock.SetDeadline(time.Time{})
	conn := &Conn{conn: sock, local: local, remote: remote, closed: false, quit: make(chan bool), tmp: make([]byte, pipe.ReadBufferSize), sendChan: make(chan string), recvChan: make(chan cache)}
	debug("create", id)
	conn.kcp = ikcp.Ikcp_create(uint32(id), conn)
	conn.kcp.Output = udp_output
	ikcp.Ikcp_wndsize(conn.kcp, 128, 128)
	ikcp.Ikcp_nodelay(conn.kcp, 1, 10, 2, 1)
	return conn
}

func (c *Conn) GetSock() *net.UDPConn {
	return c.conn
}
func (c *Conn) OnUpdate() {
	updateChan := time.NewTicker(20 * time.Millisecond)
	s := make(chan []byte)
	go func() {
		//c.conn.SetReadDeadline(time.Now().Add(time.Second))
		c.conn.SetReadDeadline(time.Time{})
		for {
			n, addr, err := c.conn.ReadFromUDP(c.tmp)
			if addr == nil || err != nil {
				if neterr, ok := err.(net.Error); ok && neterr.Timeout() {
					continue
				} else {
					break
				}
			}
			b := make([]byte, n)
			copy(b, c.tmp[:n])
			select {
			case <-c.quit:
			case s <- b:
			}
		}
	}()
	processBuffer := make([]byte, pipe.ReadBufferSize)
	var waitRecvCache *cache
	f := func(ca cache) {
		tmp := processBuffer
		hr := ikcp.Ikcp_recv(c.kcp, tmp, pipe.ReadBufferSize)
		if hr > 0 {
			copy(ca.b, tmp[:hr])
			if c.decode != nil {
				d := c.decode(ca.b[:hr])
				copy(ca.b, d)
				hr = int32(len(d))
			}
			ca.c <- int(hr)
			waitRecvCache = nil
		} else {
			waitRecvCache = &ca
		}
	}
out:
	for {
		select {
		case b := <-s:
			if len(b) <= 5 {
				break
			}
			ikcp.Ikcp_input(c.kcp, b, len(b))
			if waitRecvCache != nil {
				f(*waitRecvCache)
			}
		case s := <-c.sendChan:
			if !c.closed {
				b := []byte(s)
				ikcp.Ikcp_send(c.kcp, b, len(b))
			}
		case ca := <-c.recvChan:
			f(ca)
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
func (c *Conn) Read(p []byte) (n int, err error) {
	wc := cache{p, 0, make(chan int)}
	select {
	case c.recvChan <- wc:
		select {
		case n = <-wc.c:
		case <-c.quit:
			n = -1
		}
	case <-c.quit:
		n = -1
	}
	if n == -1 {
		return 0, errors.New("force quit for read error")
	} else {
		return n, nil
	}
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
	c.sendChan <- string(b[:sendL])
	return sendL, nil
}

func (c *Conn) Close() error {
	if !c.closed {
		c.closed = true
	}
	if c.quit != nil {
		close(c.quit)
		c.quit = nil
	}
	if c.sendChan != nil {
		close(c.sendChan)
		c.sendChan = nil
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
