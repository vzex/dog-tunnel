package nat

import (
	"bytes"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"time"
)

const (
	normalMsg = byte(iota)
	confirmMsg
	pingMsg
)

//func log.Println(...interface{}) {}
type Conn struct {
	conn           *net.UDPConn
	local, remote  net.Addr
	sendRetryTimes int
	currSendId     int32
	currRecvId     int32
	bWaitCheck     bool
	success        chan bool
	lastSendData   []byte
	tmp            []byte
	lastSendTime   int64
	lastRecvTime   int64
	closed         bool
	quit           chan bool
}

func newConn(sock *net.UDPConn, local, remote net.Addr) *Conn {
	sock.SetDeadline(time.Time{})
	t := time.Now().Unix()
	conn := &Conn{conn: sock, local: local, remote: remote, bWaitCheck: false, success: make(chan bool), tmp: make([]byte, 2000), lastSendTime: 0, lastRecvTime: t, closed: false, quit: make(chan bool), currRecvId: -1}
	go func() {
		if !conn.closed {
			defer func() {
				if err := recover(); err != nil {
					log.Println(err)
				}
			}()
			conn.success <- true
		}
	}()
	go conn.onCheck()
	return conn
}

func (c *Conn) onCheck() {
	checkChan := time.Tick(100 * time.Millisecond)
	pingChan := time.Tick(10 * time.Second)
out:
	for {
		select {
		case <-checkChan:
			//log.Println("oncheck", c.lastSendTime, c.lastRecvTime)
			if time.Now().Unix()-c.lastRecvTime > 60 {
				log.Println("connect error!,for shutdown")
				c.Close()
				break out
			}
			if c.lastSendTime > 0 && (time.Now().UnixNano()-c.lastSendTime > 200 * int64(time.Millisecond)) {
				//not receive ack data, force ok
				c.sendRetryTimes++
				if true /*c.sendRetryTimes < 30*/ {
					log.Println(">>>retry!", c.currSendId, c.sendRetryTimes)
					//send again
					buf2 := new(bytes.Buffer)
					binary.Write(buf2, binary.BigEndian, normalMsg)
					id := c.currSendId
					binary.Write(buf2, binary.BigEndian, id)
					buf2.Write(c.lastSendData)
					c.conn.WriteTo(buf2.Bytes(), c.remote)
					continue
				} else {
					log.Println("timeout wait, force ok")
					c.sendOK(-1)
				}
			}
		case <- pingChan:
			buf := new(bytes.Buffer)
			binary.Write(buf, binary.BigEndian, pingMsg)
			var id int32 = -1
			binary.Write(buf, binary.BigEndian, id)
			c.conn.WriteTo(buf.Bytes(), c.remote)
		case <-c.quit:
			break out
		}
	}
}

func (c *Conn) getNextId(id int32) int32 {
	if id < 10000 {
		id++
	} else {
		id = 0
	}
	return id
}
func (c *Conn) sendOK(checkId int32) {
	if !c.bWaitCheck { return }
	if checkId != -1 && c.currSendId != checkId { return }
	log.Println("<<<response write success", c.currSendId)
	c.currSendId = c.getNextId(c.currSendId)
	c.sendRetryTimes = 0
	c.lastSendTime = 0
	c.bWaitCheck = false
	// empty the channel
	if c.closed {
		return
	}
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
		}
	}()
	c.success <- true
}
func (c *Conn) Read(b []byte) (int, error) {
	for !c.closed {
		n, addr, err := c.conn.ReadFrom(c.tmp)
		//log.Println("<<<want read!", n, addr, err)
		// Generic non-address related errors.
		if addr == nil && err != nil {
			log.Println("<<<read error:", err.Error())
			return n, err
		}
		// Filter out anything not related to the address we care
		// about.
		if addr.Network() != c.remote.Network() || addr.String() != c.remote.String() {
			continue
		}
		buf := bytes.NewReader(c.tmp[0:n])
		var recvType byte
		err = binary.Read(buf, binary.BigEndian, &recvType)
		if err != nil {
			log.Println("<<<read type fail", buf)
			continue
		}
		var id int32
		err = binary.Read(buf, binary.BigEndian, &id)
		if err != nil {
			log.Println("<<<read id fail", buf)
			continue
		}
		c.lastRecvTime = time.Now().Unix()
		//log.Println("switch msg!", n, string(c.tmp[0:n]), recvType, id)
		if recvType == confirmMsg {
			if c.bWaitCheck {
				//for sender
				if id == c.currSendId {
					//check success
					go c.sendOK(id)
					continue
				} else {
					c.sendRetryTimes++
					if true /*c.sendRetryTimes < 30*/ {
						log.Println(">>>retry!", c.currSendId)
						//send again
						buf2 := new(bytes.Buffer)
						binary.Write(buf2, binary.BigEndian, normalMsg)
						id := c.currSendId
						binary.Write(buf2, binary.BigEndian, id)
						buf2.Write(c.lastSendData)
						c.conn.WriteTo(buf2.Bytes(), c.remote)
						continue
					} else {
						//give up, just ingore
						log.Println("<<<giveup", c.currSendId)
						go c.sendOK(-1)
						continue
					}
				}
			} else {
				log.Println("<<<no need confirm, drop data", string(c.tmp[0:n]))
				continue
			}
		} else if recvType == normalMsg {
			//for receiver
			log.Println("<<<receiver check ok msg", id, n, err)
			buf2 := new(bytes.Buffer)
			binary.Write(buf2, binary.BigEndian, confirmMsg)
			binary.Write(buf2, binary.BigEndian, id)
			c.conn.WriteTo(buf2.Bytes(), c.remote)
			if c.currRecvId != id {
				c.currRecvId = id
				n, err = buf.Read(b)
			} else {
				log.Println("receive again drop", id)
				continue
			}
			//log.Println(">>>send the ack", id)
			//send back check info
		} else if recvType == pingMsg {
			//log.Println("<<<recv ping!")
			continue
		}
		return n, err
	}
	return 0, errors.New("force quit")
}

// type 0, check, 1 msg
func (c *Conn) Write(b []byte) (int, error) {
	// wait for channel empty
	if c.closed {
		return 0, errors.New("eof")
	}
	log.Println(">>>wait to write", c.currSendId, len(b))
	//c.success <- true
	<-c.success
	log.Println(">>>write success", c.currSendId)
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, normalMsg)
	id := c.currSendId
	binary.Write(buf, binary.BigEndian, id)
	buf.Write(b)
	c.bWaitCheck = true
	c.lastSendData = b
	c.lastSendTime = time.Now().UnixNano()
	return c.conn.WriteTo(buf.Bytes(), c.remote)
}

func (c *Conn) Close() error {
	if !c.closed {
		c.closed = true
		close(c.success)
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
