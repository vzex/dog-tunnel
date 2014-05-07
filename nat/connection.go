package nat

import (
	"bytes"
	"encoding/binary"
	"errors"
	"flag"
	"log"
	"net"
	"sync"
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

type Conn struct {
	conn                  *net.UDPConn
	local, remote         net.Addr
	sendRetryTimes        int
	currSendId            int32
	currRecvId            int32
	bWaitCheck            bool
	success               chan bool
	lastSendData          [][]byte
	tmp                   []byte
	tmpForScan            []byte
	reScanPos, reScanSize int
	lastSendTime          int64
	lastRecvTime          int64
	closed                bool
	quit                  chan bool
	waitForSendBuf        [][]byte
	
	adv	sync.RWMutex
	sync.Mutex
}

func newConn(sock *net.UDPConn, local, remote net.Addr) *Conn {
	sock.SetDeadline(time.Time{})
	t := time.Now().Unix()
	conn := &Conn{conn: sock, local: local, remote: remote, bWaitCheck: false, success: make(chan bool), tmp: make([]byte, defaultPipeBuffSize), tmpForScan: make([]byte, defaultPipeBuffSize), lastSendTime: 0, lastRecvTime: t, closed: false, quit: make(chan bool), currRecvId: -1, reScanPos: 0, reScanSize: 0}
	conn.waitForSendBuf = make([]([]byte), defaultQueueSize)[:0]
	conn.lastSendData = make([]([]byte), defaultQueueSize)[:0]
	go func() {
		if !conn.closed {
			defer func() {
				if err := recover(); err != nil {
					debug(err)
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
			//debug("oncheck", c.lastSendTime, c.lastRecvTime)
			c.adv.RLock()
			if time.Now().Unix()-c.lastRecvTime > 60 {
				debug("connect error!,for shutdown")
				c.Close()
				c.adv.RUnlock()
				break out
			}
			if c.lastSendTime > 0 && (time.Now().UnixNano()-c.lastSendTime > 200*int64(time.Millisecond)) {
				//not receive ack data, force ok
				c.sendRetryTimes++
				//send again
				id := c.currSendId
				sendBuff := c.lastSendData
				totalL := len(sendBuff)
				sendL := 0
				var err error
				for i:= 0; i < totalL; i++ {
					buf := new(bytes.Buffer)
					binary.Write(buf, binary.BigEndian, normalMsg)
					binary.Write(buf, binary.BigEndian, id)
					buf.Write(sendBuff[i])
					sendl, _err := c.conn.WriteTo(buf.Bytes(), c.remote)
					if _err != nil {
						err = _err
						log.Println("write udp pipe error", err.Error())
						break
					}
					sendL += sendl
				}
				debug(">>>retry!", c.currSendId, c.sendRetryTimes, sendL)

				c.adv.RUnlock()
				continue
			}
			c.adv.RUnlock()
		case <-pingChan:
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
	c.adv.Lock()
	defer c.adv.Unlock()
	if !c.bWaitCheck {
		return
	}
	if checkId != -1 && c.currSendId != checkId {
		return
	}
	debug("<<<response write success", c.currSendId)
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
			debug(err)
		}
	}()
	c.success <- true
}
func (c *Conn) Read(b []byte) (int, error) {
	for !c.closed {
		if c.reScanPos > 0 {
			id := c.currRecvId
			n := 0
			size := cap(b)
			pre := c.reScanPos
			tempBuf := c.tmpForScan[c.reScanPos:c.reScanSize]
			tempBufL := len(tempBuf)
			if size < tempBufL {
				// not enough buff for recv msg
				copy(b, tempBuf[:size])
				c.reScanPos += size
				n = size
			} else {
				copy(b, tempBuf)
				c.reScanPos = 0
				n = tempBufL
			}
			debug("<<<continue receive check ok msg", id, n, size, tempBufL, pre)
			return n, nil
		}
		n, addr, err := c.conn.ReadFrom(c.tmp)
		if addr == nil && err != nil {
			debug("<<<read error:", err.Error())
			return n, err
		}
		if addr.Network() != c.remote.Network() || addr.String() != c.remote.String() {
			continue
		}
		//debug("<<<want read!", n, addr, err)
		// Generic non-address related errors.
		buf := bytes.NewReader(c.tmp[0:n])
		var recvType byte
		err = binary.Read(buf, binary.BigEndian, &recvType)
		if err != nil {
			debug("<<<read type fail", buf)
			continue
		}
		var id int32
		err = binary.Read(buf, binary.BigEndian, &id)
		if err != nil {
			debug("<<<read id fail", buf)
			continue
		}
		c.lastRecvTime = time.Now().Unix()
		//debug("switch msg!", n, string(c.tmp[0:n]), recvType, id)
		if recvType == confirmMsg {
			if c.bWaitCheck {
				//for sender
				c.adv.RLock()
				if id == c.currSendId {
					//check success
					c.adv.RUnlock()
					go c.sendOK(id)
					continue
				} else {
					c.adv.RUnlock()
					c.sendRetryTimes++
					continue
				}
			} else {
				debug("<<<no need confirm, drop data", id, string(c.tmp[0:n]))
				continue
			}
		} else if recvType == normalMsg {
			//for receiver
			buf2 := new(bytes.Buffer)
			binary.Write(buf2, binary.BigEndian, confirmMsg)
			binary.Write(buf2, binary.BigEndian, id)
			c.conn.WriteTo(buf2.Bytes(), c.remote)
			if c.currRecvId != id {
				c.currRecvId = id
				size := cap(b)
				if size < n-10 {
					// not enough buff for recv msg
					n, err = buf.Read(c.tmpForScan)
					log.Println("receive big data", n)
					c.reScanPos = size
					c.reScanSize = n
					n = size
					copy(b, c.tmpForScan[:size])
				} else {
					n, err = buf.Read(b)
				}
				debug("<<<receive check ok msg", id, n, err)
			} else {
				debug("<<<receive again drop", id, n)
				continue
			}
			//debug(">>>send the ack", id)
			//send back check info
		} else if recvType == pingMsg {
			//debug("<<<recv ping!")
			continue
		}
		return n, err
	}
	return 0, errors.New("force quit")
}

// type 0, check, 1 msg
func (c *Conn) Write(b []byte) (int, error) {
	c.Lock()
	//defer c.Unlock()
	// wait for channel empty
	if c.closed {
		c.Unlock()
		return 0, errors.New("eof")
	}
	oldL := len(c.waitForSendBuf)
	newL := len(b)
	oldSendId := c.currSendId
	debug(">>>wait to write", newL, "queue size", oldL, oldSendId)
	bBuffed := true
	if oldL+1> defaultQueueSize {
		bBuffed = false
		<-c.success
	} else {
		c.waitForSendBuf = append(c.waitForSendBuf, b)
		if oldL == 0 {
			c.Unlock()
			<-c.success
		} else {
			c.Unlock()
			return 0, nil
		}
	}
	sendBuff := c.waitForSendBuf
	if !bBuffed {
		c.waitForSendBuf = [][]byte{b}
		sendBuff = c.waitForSendBuf
	}
	totalL := len(sendBuff)
	sendL := 0
	var err error
	id := c.currSendId
	debug(">>>write begin", id, "bytes, buffed:", bBuffed, "queue size", totalL, oldSendId)
	for i:= 0; i < totalL; i++ {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.BigEndian, normalMsg)
		binary.Write(buf, binary.BigEndian, id)
		buf.Write(sendBuff[i])
		sendl, _err := c.conn.WriteTo(buf.Bytes(), c.remote)
		if _err != nil {
			err = _err
			log.Println("write udp pipe error", err.Error())
			break
		}
		//debug("send", string(sendBuff[i]))
		sendL += sendl
	}
	c.bWaitCheck = true
	c.adv.Lock()
	defer c.adv.Unlock()
	c.lastSendData = c.lastSendData[:totalL]
	for i, _ := range sendBuff {
		copy(c.lastSendData[i], sendBuff[i])
	}
	c.lastSendTime = time.Now().UnixNano()
	if bBuffed {
		c.waitForSendBuf = c.waitForSendBuf[:0]
	} else {
		c.Unlock()
	}
	debug(">>>write succeed", sendL, totalL, oldSendId)
	return sendL, err
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
