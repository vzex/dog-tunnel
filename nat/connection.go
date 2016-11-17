package nat

import "github.com/vzex/dog-tunnel/ikcp"
import "github.com/klauspost/reedsolomon"
import "github.com/cznic/zappy"

import (
	"errors"
	"flag"
	"log"
	//"math/rand"
	"net"
	"time"
)

const (
	Ping byte = 1
	Data byte = 2

	FecData byte = 1
	FecOver byte = 2
)

var bDebug = flag.Bool("debug", false, "whether show nat pipe debug msg")
var bCompress = flag.Bool("compress", false, "whether compress data, two sides should be same")

var defaultQueueSize = 1

const dataLimit = 4000
const SendBuffSize = 2000
const CacheBuffSize = SendBuffSize + 1000

func debug(args ...interface{}) {
	if *bDebug {
		log.Println(args...)
	}
}
func iclock() int32 {
	return int32((time.Now().UnixNano() / 1000000) & 0xffffffff)
}

func udp_output(buf []byte, _len int32, kcp *ikcp.Ikcpcb, user interface{}) int32 {
	//debug("write!!!", _len)
	c := user.(*Conn)
	c.output(buf[:_len])
	return 0
}

type cache struct {
	b []byte
	l int
	c chan int
}

type fecInfo struct {
	bytes    [][]byte
	overTime int64
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

	fecDataShards   int
	fecParityShards int
	fecW            *reedsolomon.Encoder
	fecR            *reedsolomon.Encoder
	fecRCacheTbl    map[uint]*fecInfo
	fecWCacheTbl    *fecInfo
	fecWriteId      uint //uint16
	fecSendC        uint
	fecSendL        int
	fecRecvId       uint

	compressCache []byte
}

type KcpSetting struct {
	Nodelay  int32
	Interval int32 //not for set
	Resend   int32
	Nc       int32

	Sndwnd int32
	Rcvwnd int32

	Mtu int32

	//Xor string
}

func DefaultKcpSetting() *KcpSetting {
	return &KcpSetting{Nodelay: 1, Interval: 10, Resend: 2, Nc: 1, Sndwnd: 1024, Rcvwnd: 1024, Mtu: 1400}
}

func newConn(sock *net.UDPConn, local, remote net.Addr, id int) *Conn {
	sock.SetDeadline(time.Time{})
	conn := &Conn{conn: sock, local: local, remote: remote, closed: false, quit: make(chan bool), tmp: make([]byte, CacheBuffSize), tmp2: make([]byte, CacheBuffSize), sendChan: make(chan string, 10), checkCanWrite: make(chan chan bool), readChan: make(chan cache), overTime: time.Now().Unix() + 30, fecWriteId: 0, fecSendC: 0}
	debug("create", id)
	conn.kcp = ikcp.Ikcp_create(uint32(id), conn)
	conn.kcp.Output = udp_output
	conn.SetKcp(DefaultKcpSetting())
	if *bCompress {
		conn.compressCache = make([]byte, CacheBuffSize*2)
	}
	return conn
}

func (c *Conn) SetKcp(setting *KcpSetting) {
	ikcp.Ikcp_wndsize(c.kcp, setting.Sndwnd, setting.Rcvwnd)
	ikcp.Ikcp_nodelay(c.kcp, setting.Nodelay, setting.Interval, setting.Resend, setting.Nc)
	ikcp.Ikcp_setmtu(c.kcp, setting.Mtu)
}
func (c *Conn) SetFec(DataShards, ParityShards int) (er error) {
	c.fecDataShards = DataShards
	c.fecParityShards = ParityShards
	var fec reedsolomon.Encoder
	fec, er = reedsolomon.New(DataShards, ParityShards)
	if er != nil {
		return
	}
	c.fecR = &fec
	fec, er = reedsolomon.New(DataShards, ParityShards)
	if er == nil {
		c.fecRCacheTbl = make(map[uint]*fecInfo)
		c.fecWCacheTbl = nil
		c.fecW = &fec
	} else {
		c.fecR = nil
	}
	return
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
	processRecv := func() {
		if waitRecvCache != nil {
			ca := *waitRecvCache
			for {
				hr := ikcp.Ikcp_recv(c.kcp, c.tmp2, CacheBuffSize)

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
	}
out:
	for {
		select {
		case <-ping:
			pingC++
			if pingC >= 4 {
				pingC = 0
				go c.Ping()
				if c.fecR != nil {
					curr := time.Now().Unix()
					for id, info := range c.fecRCacheTbl {
						if curr >= info.overTime {
							delete(c.fecRCacheTbl, id)
							if c.fecRecvId <= id {
								c.fecRecvId = id + 1
							}
							//log.Println("timeout after del", id, len(c.fecRCacheTbl))
						}
					}
				}
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
				hr := ikcp.Ikcp_recv(c.kcp, c.tmp2, CacheBuffSize)
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
			if *bCompress {
				_b, _er := zappy.Decode(nil, b)
				if _er != nil {
					log.Println("decompress fail", _er.Error())
					go c.Close()
					break
				}
				//log.Println("decompress", len(_b), len(b))
				b = _b
			}
			if c.fecR != nil {
				if len(b) <= 7 {
					break
				}
				id := uint(int(b[2]) | (int(b[3]) << 8) | (int(b[4]) << 16) | (int(b[5]) << 24))
				var seq = uint(b[6])
				_len := int(b[0]) | (int(b[1]) << 8)
				//log.Println("recv chan", len(b), _len, id, seq, c.fecRecvId)
				if id < c.fecRecvId {
					//log.Println("drop id for noneed", id, seq)
					break
				}
				if seq < uint(c.fecDataShards) {
					ikcp.Ikcp_input(c.kcp, b[7:], _len)
					//log.Println("direct input udp", id, seq, _len)
				}
				if seq >= uint(c.fecDataShards+c.fecParityShards) {
					log.Println("-ds and -ps must be equal on both sides")
					go c.Close()
					break
				}
				tbl, have := c.fecRCacheTbl[id]
				if !have {
					tbl = &fecInfo{make([][]byte, c.fecDataShards+c.fecParityShards), time.Now().Unix() + 15}
					c.fecRCacheTbl[id] = tbl
				}
				if tbl.bytes[seq] != nil {
					//dup, drop
					break
				} else {
					tbl.bytes[seq] = b
				}
				count := 0
				reaL := 0
				for _, v := range tbl.bytes {
					if v != nil {
						count++
						if reaL < len(v) {
							reaL = len(v)
						}
					}
				}
				if count >= c.fecDataShards {
					markTbl := make(map[int]bool, len(tbl.bytes))
					for _seq := range tbl.bytes {
						markTbl[_seq] = true
					}
					for i, v := range tbl.bytes {
						if v != nil {
							if len(v) < reaL {
								_b := make([]byte, reaL)
								copy(_b, v)
								tbl.bytes[i] = _b
							}
						}
					}
					er := (*c.fecR).Reconstruct(tbl.bytes)
					if er != nil {
						//log.Println("Reconstruct fail", er.Error())
						break
					} else {
						//log.Println("Reconstruct ok, input", id)
						for i := 0; i < c.fecDataShards; i++ {
							if _, have := markTbl[i]; !have {
								_len := int(tbl.bytes[i][0]) | (int(tbl.bytes[i][1]) << 8)
								ikcp.Ikcp_input(c.kcp, tbl.bytes[i][7:], int(_len))
								//log.Println("fec input for mark ok", i, id, _len)
							}
						}
					}
					delete(c.fecRCacheTbl, id)
					//log.Println("after del", id, len(c.fecRCacheTbl))
					if c.fecRecvId <= id {
						c.fecRecvId = id + 1
					}
				}
			} else {
				ikcp.Ikcp_input(c.kcp, b, len(b))
			}
			processRecv()
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

func (c *Conn) writeTo(b []byte) {
	if *bCompress {
		enc, er := zappy.Encode(c.compressCache, b)
		if er != nil {
			log.Println("compress error", er.Error())
			go c.Close()
			return
		}
		//log.Println("compress", len(b), len(enc))
		c.conn.WriteTo(enc, c.remote)
	} else {
		c.conn.WriteTo(b, c.remote)
	}
}
func (c *Conn) output(b []byte) {
	if c.fecW == nil {
		c.writeTo(b)
	} else {
		id := c.fecWriteId
		c.fecSendC++

		info := c.fecWCacheTbl
		if info == nil {
			info = &fecInfo{make([][]byte, c.fecDataShards+c.fecParityShards), time.Now().Unix() + 15}
			c.fecWCacheTbl = info
		}
		_b := make([]byte, len(b)+7)
		_len := len(b)
		_b[0] = byte(_len & 0xff)
		_b[1] = byte((_len >> 8) & 0xff)
		_b[2] = byte(id & 0xff)
		_b[3] = byte((id >> 8) & 0xff)
		_b[4] = byte((id >> 16) & 0xff)
		_b[5] = byte((id >> 32) & 0xff)
		_b[6] = byte(c.fecSendC - 1)
		copy(_b[7:], b)
		info.bytes[c.fecSendC-1] = _b
		if c.fecSendL < len(_b) {
			c.fecSendL = len(_b)
		}
		//if rand.Intn(100) > 20 {
		c.writeTo(_b)
		//log.Println("output udp id", id, _len, len(_b))
		//}
		if c.fecSendC >= uint(c.fecDataShards) {
			for i := 0; i < c.fecDataShards; i++ {
				if c.fecSendL > len(info.bytes[i]) {
					__b := make([]byte, c.fecSendL)
					copy(__b, info.bytes[i])
					info.bytes[i] = __b
				}
			}
			for i := 0; i < c.fecParityShards; i++ {
				info.bytes[i+c.fecDataShards] = make([]byte, c.fecSendL)
			}
			er := (*c.fecW).Encode(info.bytes)
			if er != nil {
				log.Println("encode err", er.Error())
				go c.Close()
				return
			}
			for i := c.fecDataShards; i < c.fecDataShards+c.fecParityShards; i++ {
				_info := info.bytes[i]
				//if rand.Intn(100) > 20 {
				c.writeTo(_info)
				//_len := int(_info[0]) | (int(_info[1]) << 8)
				//log.Println("output udp id fec", id, i, _len, len(_info))
				//}
			}
			c.fecWCacheTbl = nil
			c.fecSendC = 0
			c.fecSendL = 0
			c.fecWriteId++
			//log.Println("flush id", id)
		}
		//log.Println("output sn", c.fecWriteId, c.fecSendC, _len)
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
