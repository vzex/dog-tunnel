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
	normalMsg = byte(iota)
	confirmMsg
	pingMsg
)

var bDebug = flag.Bool("debug", false, "whether show nat pipe debug msg")

var defaultQueueSize = 1
var defaultPipeBuffSize = 20000

func debug(args ...interface{}) {
	if *bDebug {
		log.Println(args...)
	}
}
func iclock() int32 {
        return int32((time.Now().UnixNano()/1000000) & 0xffffffff)
}

func udp_output(buf []byte, _len int32, kcp *ikcp.Ikcpcb, user interface{}) int32 {
        debug("write!!!", _len)
        c := user.(*Conn)
        c.conn.WriteTo(buf[:_len], c.remote)
	return 0
}

type Conn struct {
	conn                  *net.UDPConn
	local, remote         net.Addr
	closed                bool
	quit                  chan bool
        kcp                *ikcp.Ikcpcb
        
        tmp                     []byte
}

func newConn(sock *net.UDPConn, local, remote net.Addr, id int) *Conn {
	sock.SetDeadline(time.Time{})
        conn := &Conn{conn: sock, local: local, remote: remote, closed: false, quit: make(chan bool), tmp:make([]byte, 2000)}
        debug("create", id)
        conn.kcp = ikcp.Ikcp_create(uint32(id), conn)
        conn.kcp.Output = udp_output
	ikcp.Ikcp_wndsize(conn.kcp, 128, 128)
        ikcp.Ikcp_nodelay(conn.kcp, 1, 10, 2, 1)
	go conn.onUpdate()
	return conn
}

func (c *Conn) onUpdate() {
	updateChan := time.Tick(20* time.Millisecond)
out:
	for {
		select {
		case <-updateChan:
                        if c.closed {break out}
                        ikcp.Ikcp_update(c.kcp, uint32(iclock()))
		case <-c.quit:
			break out
		}
	}
}
func (c *Conn) Read(b []byte) (int, error) {
        if !c.closed {
                for {
                        hr := ikcp.Ikcp_recv(c.kcp, c.tmp, 2000)
                        if hr > 0 {
                                debug("read", hr)
                                copy(b, c.tmp[:hr])
                                return int(hr), nil
                        }
                        bHave := false
                        for {
                                n, addr, err := c.conn.ReadFrom(c.tmp)
                                //debug("want read!", n, addr, err)
                                // Generic non-address related errors.
                                if addr == nil && err != nil {
                                        debug("error!", err.Error())
                                        return 0, err
                                }
                                //debug("redirect", n)
                                ikcp.Ikcp_input(c.kcp, c.tmp[:n], n)
                                bHave = true
                                break
                        }
                        if !bHave {
                                time.Sleep(10 * time.Millisecond)
                        }

                }
        }
        return 0, errors.New("force quit")
}

// type 0, check, 1 msg
func (c *Conn) Write(b []byte) (int, error) {
        if c.closed {return 0, errors.New("eof")}

        sendL := len(b)
        debug("try write", sendL)
        ikcp.Ikcp_send(c.kcp, b, sendL)
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
