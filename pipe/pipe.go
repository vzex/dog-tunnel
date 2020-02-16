package pipe

import (
	"encoding/binary"
	"errors"
	"github.com/vzex/dog-tunnel/common"
	"github.com/vzex/dog-tunnel/ikcp"
	"log"
	"math/rand"
	"net"
	"sync"
	"time"
)
import "github.com/klauspost/reedsolomon"
import "github.com/vzex/zappy"

const WriteBufferSize = 5000               //udp writer will add some data for checksum or encrypt
const ReadBufferSize = WriteBufferSize * 2 //so reader must be larger

const dataLimit = WriteBufferSize

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

type fecInfo struct {
	bytes    [][]byte
	overTime int64
}

func iclock() int32 {
	return int32((time.Now().UnixNano() / 1000000) & 0xffffffff)
}

func udp_output(buf []byte, _len int32, kcp *ikcp.Ikcpcb, user interface{}) int32 {
	c := user.(*UDPMakeSession)
	//log.Println("send udp", _len, c.remote.String())
	c.output(buf[:_len])
	return 0
}

const (
	Reset     byte = 0
	FirstSYN  byte = 6
	FirstACK  byte = 1
	SndSYN    byte = 2
	SndACK    byte = 2
	Data      byte = 4
	Ping      byte = 5
	Close     byte = 7
	CloseBack byte = 8
	ResetAck  byte = 9

	Fake byte = 50
)

func __xor(s []byte, xor string) []byte {
	if len(xor) == 0 {
		return s
	}
	encodingData := []byte(xor)
	encodingLen := len(encodingData)
	n := len(s)
	if n == 0 {
		return s
	}
	for i := 0; i < n; i++ {
		s[i] = s[i] ^ encodingData[i%encodingLen]
	}
	return s
}

func _xor(s []byte, xor string) []byte {
	if len(xor) == 0 {
		return s
	}
	encodingData := []byte(xor)
	encodingLen := len(encodingData)
	n := len(s)
	if n == 0 {
		return s
	}
	r := make([]byte, n)
	for i := 0; i < n; i++ {
		r[i] = s[i] ^ encodingData[i%encodingLen]
	}
	return r
}

func makeEncode(buf []byte, status byte, arg int, arg2 int16, xor string) []byte {
	buf[0] = status
	binary.LittleEndian.PutUint32(buf[1:], uint32(arg))
	binary.LittleEndian.PutUint16(buf[5:], uint16(arg2))
	return _xor(buf, xor)
}

func makeDecode(data []byte, xor string) (status byte, arg int32, arg2 int16) {
	if len(data) < 7 {
		return Reset, 0, 0
	}
	data = _xor(data, xor)
	status = data[0]
	arg = int32(binary.LittleEndian.Uint32(data[1:5]))
	arg2 = int16(binary.LittleEndian.Uint16(data[5:7]))
	return
}

type UDPMakeSession struct {
	id                int
	idstr             string
	status            string
	overTime          int64
	quitChan          chan struct{}
	closeChan         chan struct{}
	recvChan          chan cache
	handShakeChan     chan string
	handShakeChanQuit chan struct{}
	sock              *net.UDPConn
	remote            *net.UDPAddr
	kcp               *ikcp.Ikcpcb
	do                chan Action
	do2               chan Action
	checkCanWrite     chan (chan struct{})
	listener          *Listener
	closed            bool

	readBuffer    []byte
	processBuffer []byte
	encodeBuffer  []byte
	timeout       int64

	xor string

	compressCache   []byte
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

	confuseSeed int
}

type Listener struct {
	connChan     chan *UDPMakeSession
	quitChan     chan struct{}
	sock         *net.UDPConn
	readBuffer   []byte
	sessions     map[string]*UDPMakeSession
	sessionsLock sync.RWMutex
	setting      *KcpSetting
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
	l.sessionsLock.RLock()
	defer l.sessionsLock.RUnlock()
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
			l.sessionsLock.RLock()
			session, bHave := l.sessions[addr]
			l.sessionsLock.RUnlock()
			if bHave {
				if session.status == "ok" {
					if session.remote.String() == from.String() && (n >= int(ikcp.IKCP_OVERHEAD) || session.compressCache != nil) {
						__xor(l.readBuffer, session.xor)
						var buf []byte
						if n <= 7 || session.compressCache == nil {
							buf = make([]byte, n)
							copy(buf, l.readBuffer[:n])
						} else {
							_b, _er := zappy.Decode(nil, l.readBuffer[:n])
							if _er != nil {
								log.Println("decompress fail", _er.Error())
								//go session.Close()
								//don't close pipe, just drop this data
								continue
							}
							buf = _b
							//log.Println("decompress", n, len(_b))
						}
						session.DoAction2("input", buf, len(buf))
					}
					continue
				} else {
					session.serverDo(string(l.readBuffer[:n]))
				}
			} else {
				status, _, fec := makeDecode(l.readBuffer[:n], l.setting.Xor)
				if status != FirstSYN {
					go sock.WriteToUDP([]byte("0"), from)
					log.Println("invalid package,reset", from, status)
					continue
				}
				sessionId := common.GetId("udp")
				session = &UDPMakeSession{status: "init", overTime: time.Now().Unix() + 10, remote: from, sock: sock, recvChan: make(chan cache), quitChan: make(chan struct{}), readBuffer: make([]byte, ReadBufferSize*2), processBuffer: make([]byte, ReadBufferSize), timeout: 30, do: make(chan Action), do2: make(chan Action), id: sessionId, handShakeChan: make(chan string), handShakeChanQuit: make(chan struct{}), listener: l, closeChan: make(chan struct{}), encodeBuffer: make([]byte, 7), checkCanWrite: make(chan (chan struct{})), xor: l.setting.Xor}
				if fec & ^(1<<7) != 0 {
					er := session.SetFec((int(fec)>>8)&0xff, int(fec&^(1<<7)&0xff))
					if er != nil {
						log.Println("set fec error:", fec, er.Error())
					} else {
						log.Println("set fec ok:", (int(fec)>>8)&0xff, int(fec&^(1<<7)&0xff))
					}
				}
				if int(fec)&(1<<7) != 0 {
					session.compressCache = make([]byte, zappy.MaxEncodedLen(ReadBufferSize))
				}
				l.sessionsLock.Lock()
				l.sessions[addr] = session
				l.sessionsLock.Unlock()
				session.serverInit(l, l.setting)
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
	l.sessionsLock.Lock()
	defer l.sessionsLock.Unlock()
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
	return ListenWithSetting(addr, DefaultKcpSetting())
}

func ListenWithSetting(addr string, setting *KcpSetting) (*Listener, error) {
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, err
	}
	sock, _err := net.ListenUDP("udp", udpAddr)
	if _err != nil {
		return nil, _err
	}

	listener := &Listener{connChan: make(chan *UDPMakeSession), quitChan: make(chan struct{}), sock: sock, readBuffer: make([]byte, ReadBufferSize*2), sessions: make(map[string]*UDPMakeSession), setting: setting}
	go listener.loop()
	return listener, nil
}

func Dial(addr string) (*UDPMakeSession, error) {
	return DialTimeout(addr, 30)
}

type KcpSetting struct {
	Nodelay  int32
	Interval int32 //not for set
	Resend   int32
	Nc       int32

	Sndwnd int32
	Rcvwnd int32

	Mtu int32

	Xor string
}

func DefaultKcpSetting() *KcpSetting {
	return &KcpSetting{Nodelay: 1, Interval: 10, Resend: 2, Nc: 1, Sndwnd: 1024, Rcvwnd: 1024, Mtu: 1400}
}

func DialTimeout(addr string, timeout int) (*UDPMakeSession, error) {
	return DialTimeoutWithSetting(addr, timeout, DefaultKcpSetting(), 0, 0, false, false)
}

func DialTimeoutWithSetting(addr string, timeout int, setting *KcpSetting, ds, ps int, comp, confuse bool) (*UDPMakeSession, error) {
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
	session := &UDPMakeSession{readBuffer: make([]byte, ReadBufferSize*2), do: make(chan Action), do2: make(chan Action), quitChan: make(chan struct{}), recvChan: make(chan cache), processBuffer: make([]byte, ReadBufferSize), closeChan: make(chan struct{}), encodeBuffer: make([]byte, 7), checkCanWrite: make(chan (chan struct{})), xor: setting.Xor}
	session.remote = udpAddr
	session.sock = sock
	session.status = "firstsyn"
	session.timeout = int64(timeout)
	if confuse {
		session.confuseSeed = rand.Intn(int(WriteBufferSize/2)) + 10
	}
	if ds != 0 && ps != 0 {
		er := session.SetFec(ds, ps)
		if er != nil {
			log.Println("set fec error:", er.Error())
		} else {
			log.Println("set fec ok:", ds, ps)
		}
	}
	if comp {
		session.compressCache = make([]byte, zappy.MaxEncodedLen(ReadBufferSize))
	}
	_timeout := int(timeout / 2)
	if _timeout < 5 {
		timeout = 5
	}
	arg := int(int32(timeout) + int32(mainV<<24) + int32(subV<<16))
	arg2 := int16((ds << 8) | ps)
	if comp {
		arg2 = arg2 | (1 << 7)
	} else {
		arg2 = arg2 & ^(1 << 7)
	}
	info := makeEncode(session.encodeBuffer, FirstSYN, arg, arg2, session.xor)
	code := session.doAndWait(func() {
		sock.WriteToUDP(info, udpAddr)
	}, _timeout, func(status byte, arg int32, arg2 int16) int {
		if status == ResetAck {
			_mainV, _subV := int(byte(arg>>24)), int(byte(arg>>16))
			log.Printf("pipe version not eq,%d.%d=>%d.%d", mainV, subV, _mainV, _subV)
			return 1
		}
		if status != FirstACK {
			log.Println("recv not FirstACK", status)
			return -1
		} else {
			session.status = "firstack"
			session.id = int(arg)
			return 0
		}
	})
	if code != 0 {
		log.Println("handshakefail with code", code)
		return nil, errors.New("handshake fail,1")
	}
	code = session.doAndWait(func() {
		if session.confuseSeed > 0 {
			sock.WriteToUDP(makeEncode(session.encodeBuffer, SndSYN, session.id, 1, session.xor), udpAddr)
		} else {
			sock.WriteToUDP(makeEncode(session.encodeBuffer, SndSYN, session.id, 0, session.xor), udpAddr)
		}
	}, _timeout, func(status byte, arg int32, arg2 int16) int {
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
	ikcp.Ikcp_wndsize(session.kcp, setting.Sndwnd, setting.Rcvwnd)
	ikcp.Ikcp_nodelay(session.kcp, setting.Nodelay, setting.Interval, setting.Resend, setting.Nc)
	ikcp.Ikcp_setmtu(session.kcp, setting.Mtu)
	go session.loop()
	return session, nil
}

func (session *UDPMakeSession) SetFec(DataShards, ParityShards int) (er error) {
	session.fecDataShards = DataShards
	session.fecParityShards = ParityShards
	var fec reedsolomon.Encoder
	fec, er = reedsolomon.New(DataShards, ParityShards)
	if er != nil {
		return
	}
	session.fecR = &fec
	fec, er = reedsolomon.New(DataShards, ParityShards)
	if er == nil {
		session.fecRCacheTbl = make(map[uint]*fecInfo)
		session.fecWCacheTbl = nil
		session.fecW = &fec
	} else {
		session.fecR = nil
	}
	return
}

func (session *UDPMakeSession) doAndWait(f func(), sec int, readf func(status byte, arg int32, arg2 int16) int) (code int) {
	t := time.NewTicker(50 * time.Millisecond)
	currT := time.Now().Unix()
	f()
	out:
	for {
		select {
		case <-t.C:
			if time.Now().Unix()-currT >= int64(sec) {
				log.Println("session timeout")
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
				code = readf(makeDecode(session.readBuffer[:n], session.xor))
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

func (session *UDPMakeSession) writeTo(b []byte) {
	if session.compressCache != nil && len(b) > 7 {
		enc, er := zappy.Encode(session.compressCache, b)
		if er != nil {
			log.Println("compress error", er.Error())
			go session.Close()
			return
		}
		//log.Println("compress", len(b), len(enc))
		session.sock.WriteTo(__xor(enc, session.xor), session.remote)
	} else {
		session.sock.WriteTo(__xor(b, session.xor), session.remote)
	}
}

func (session *UDPMakeSession) output(b []byte) {
	if session.fecW == nil {
		session.writeTo(b)
	} else {
		id := session.fecWriteId
		session.fecSendC++

		info := session.fecWCacheTbl
		if info == nil {
			info = &fecInfo{make([][]byte, session.fecDataShards), time.Now().Unix() + 15}
			session.fecWCacheTbl = info
		}
		_b := make([]byte, len(b)+7)
		_len := len(b)
		_b[0] = byte(_len & 0xff)
		_b[1] = byte((_len >> 8) & 0xff)
		_b[2] = byte(id & 0xff)
		_b[3] = byte((id >> 8) & 0xff)
		_b[4] = byte((id >> 16) & 0xff)
		_b[5] = byte((id >> 32) & 0xff)
		_b[6] = byte(session.fecSendC - 1)
		copy(_b[7:], b)
		info.bytes[session.fecSendC-1] = _b
		if session.fecSendL < len(_b)-7 {
			session.fecSendL = len(_b)-7
		}
		session.writeTo(_b)
		if session.fecSendC >= uint(session.fecDataShards) {
			fecData := make([][]byte, session.fecDataShards + session.fecParityShards)
			for i := 0; i < session.fecDataShards; i++ {
				if session.fecSendL > len(info.bytes[i])-7 {
					__b := make([]byte, session.fecSendL)
					copy(__b, info.bytes[i][7:])
					fecData[i] = __b
				} else {
					fecData[i] = info.bytes[i][7:]
				}
			}
			for i := 0; i < session.fecParityShards; i++ {
				fecData[i+session.fecDataShards] = make([]byte, session.fecSendL)
			}
			er := (*session.fecW).Encode(fecData)
			if er != nil {
				//log.Println("wocao encode err", er.Error())
				go session.Close()
				return
			}
			for i := session.fecDataShards; i < session.fecDataShards+session.fecParityShards; i++ {
				//if rand.Intn(100) >= 15 {
				b := fecData[i]
				_b := make([]byte, len(b)+7)
				_len := len(b)
				_b[0] = byte(_len & 0xff)
				_b[1] = byte((_len >> 8) & 0xff)
				_b[2] = byte(id & 0xff)
				_b[3] = byte((id >> 8) & 0xff)
				_b[4] = byte((id >> 16) & 0xff)
				_b[5] = byte((id >> 32) & 0xff)
				_b[6] = byte(i)
				copy(_b[7:], b)
				//log.Println("write extra", _b)
				session.writeTo(_b)
				//_len := int(_info[0]) | (int(_info[1]) << 8)
				//log.Println("output udp id", id, i, _len, len(_info))
				//} else {
				//	log.Println("drop output udp id", id, i, _len, len(_info))
				//}
			}
			session.fecWCacheTbl = nil
			session.fecSendC = 0
			session.fecSendL = 0
			session.fecWriteId++
			//log.Println("flush id", id)
		}
		//log.Println("output sn", c.fecWriteId, c.fecSendC, _len)
	}
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
func (session *UDPMakeSession) serverInit(l *Listener, setting *KcpSetting) {
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
		for {
			select {
			case s := <-session.handShakeChan:
				//log.Println("process handshake", session.remote)
				status, arg, arg2 := makeDecode([]byte(s), session.xor)
				switch session.status {
				case "init":
					if status != FirstSYN {
						log.Println("status != FirstSYN, reset", session.remote, status)
						session.sock.WriteToUDP(makeEncode(session.encodeBuffer, Reset, 0, 0, session.xor), session.remote)
						return
					}
					_mainV, _subV := int(byte(arg>>24)), int(byte(arg>>16))
					if _mainV != mainV || _subV != subV {
						session.sock.WriteToUDP(makeEncode(session.encodeBuffer, ResetAck, (mainV<<24)+(subV<<16), 0, session.xor), session.remote)
						log.Printf("pipe version not eq,kickout,%d.%d=>%d.%d", mainV, subV, _mainV, _subV)
						return
					}
					session.status = "firstack"
					session.timeout = int64(arg & 0xff)
					session.sock.WriteToUDP(makeEncode(session.encodeBuffer, FirstACK, session.id, 0, session.xor), session.remote)
					overTime = time.Now().Unix() + session.timeout
				case "firstack":
					if status != SndSYN {
						log.Println("status != SndSYN, nothing", session.remote, status)
						/*
						if status == FirstSYN {
							session.sock.WriteToUDP(makeEncode(session.encodeBuffer, FirstACK, session.id), session.remote, session.xor)
						}*/
						return
					}
					if arg2 > 0 {
						session.confuseSeed = rand.Intn(int(WriteBufferSize/2)) + 10
						log.Println("confuse!")
					}
					session.status = "ok"
					session.kcp = ikcp.Ikcp_create(uint32(session.id), session)
					session.kcp.Output = udp_output
					ikcp.Ikcp_wndsize(session.kcp, setting.Sndwnd, setting.Rcvwnd)
					ikcp.Ikcp_nodelay(session.kcp, setting.Nodelay, setting.Interval, setting.Resend, setting.Nc)
					ikcp.Ikcp_setmtu(session.kcp, setting.Mtu)
					go session.loop()
					go func() {
						select {
						case l.connChan <- session:
						case <-l.quitChan:
						}
					}()
					session.sock.WriteToUDP(makeEncode(session.encodeBuffer, SndACK, session.id, 0, session.xor), session.remote)
					overTime = time.Now().Unix() + session.timeout
				}
			case <-c.C:
				if time.Now().Unix() > overTime {
					return
				}
				switch session.status {
				case "firstack":
					session.sock.WriteToUDP(makeEncode(session.encodeBuffer, FirstACK, session.id, 0, session.xor), session.remote)
				case "ok":
					buf := make([]byte, 7)
					session.sock.WriteToUDP(makeEncode(buf, SndACK, session.id, 0, session.xor), session.remote)
				}
			}
		}
	}()
}

func (session *UDPMakeSession) loop() {
	curr := time.Now().Unix()
	session.overTime = curr + session.timeout
	ping := make(chan struct{})
	pingC := 0
	callUpdate := false
	updateC := make(chan struct{})
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
				}
				if session.remote.String() == from.String() {
					//log.Println("===", n, len(session.compressCache))
					if n >= int(ikcp.IKCP_OVERHEAD) || n <= 7 || session.compressCache != nil {
						__xor(session.readBuffer[:n], session.xor)
						var buf []byte
						if n <= 7 || session.compressCache == nil {
							buf = make([]byte, n)
							copy(buf, session.readBuffer[:n])
						} else {
							_b, _er := zappy.Decode(nil, session.readBuffer[:n])
							if _er != nil {
								log.Println("decompress fail", _er.Error())
								//go session.Close()
								//don't close pipe, just drop data
								continue
							}
							buf = _b
							//log.Println("decompress", n, len(_b))
						}
						session.DoAction2("input", buf, len(buf))
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
				case updateC <- struct{}{}:
				case <-session.quitChan:
				}
			})
		}
	}

	fastCheck := false
	waitList := [](chan struct{}){}
	recoverChan := make(chan struct{})

	var waitRecvCache *cache
	var forceWait int64 = 0
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
						go session.DoWrite(makeEncode(session.encodeBuffer, Ping, 0, 0, session.xor))
					}

					if session.fecR != nil {
						curr := time.Now().Unix()
						for id, info := range session.fecRCacheTbl {
							if curr >= info.overTime {
								delete(session.fecRCacheTbl, id)
								//log.Println("timeout after del", id, len(c.fecRCacheTbl))
							}
						}
					}
					if forceWait > 0 {
						if time.Now().Unix() > forceWait && ikcp.Ikcp_waitsnd(session.kcp) <= dataLimit/2 {
							forceWait = 0
							go func() {
								select {
								case <-session.quitChan:
								case recoverChan <- struct{}{}:
								}
							}()
						}
					}
				}
				if time.Now().Unix() > session.overTime {
					log.Println("overtime close", session.LocalAddr().String(), session.RemoteAddr().String())
					go session.Close()
				} else {
					time.AfterFunc(300*time.Millisecond, func() {
						select {
						case ping <- struct{}{}:
						case <-session.quitChan:
						}
					})
				}
			case <-recoverChan:
				fastCheck = false
				for _, r := range waitList {
					//log.Println("recover writing data")
					select {
					case r <- struct{}{}:
					case <-session.quitChan:
					}
				}
				waitList = [](chan struct{}){}
			case c := <-session.checkCanWrite:
				if session.confuseSeed > 0 {
					if WriteBufferSize/2-rand.Intn(session.confuseSeed) < 500 || rand.Intn(100) < 5 {
						//make a sleep
						forceWait = time.Now().Add(time.Millisecond * time.Duration(rand.Intn(1000))).Unix()
					}
				}
				if ikcp.Ikcp_waitsnd(session.kcp) > dataLimit {
					//log.Println("wait for data limit")
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
									log.Println("recover writing data quit")
								case recoverChan <- struct{}{}:
								}
							} else {
								updateF(20)
								time.AfterFunc(40*time.Millisecond, f)
							}
						}
						time.AfterFunc(20*time.Millisecond, f)
					}
				} else if forceWait > 0 && time.Now().Unix() < forceWait {
					waitList = append(waitList, c)
				} else {
					select {
					case c <- struct{}{}:
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
							n := 1
							l := hr
							if session.confuseSeed > 0 {
								n = 3
								l = (int32(tmp[1]) | (int32(tmp[2]) << 8)) + int32(n)
							}
							//log.Println("try recv", hr, n, l)
							copy(ca.b, tmp[n:int(l)])
							select {
							case ca.c <- int(int(l) - n):
							case <-session.quitChan:
							}
							break
						} else if status == Fake {
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

					if session.fecR != nil {
						if len(s) <= 7 {
							if n < 7 {
								log.Println("recv reset")
								go session._Close(false)
								break
							} else if n == 7 {
								status, _, _ := makeDecode(s, session.xor)
								if status == Reset || status == ResetAck {
									log.Println("recv reset2", status)
									go session._Close(false)
								}
								break
							}
							break
						}
						id := uint(int(s[2]) | (int(s[3]) << 8) | (int(s[4]) << 16) | (int(s[5]) << 24))
						var seq uint = uint(s[6])
						_len := int(s[0]) | (int(s[1]) << 8)

						//binary.Read(head[:4], binary.LittleEndian, &id)
						if seq < uint(session.fecDataShards) {
							ikcp.Ikcp_input(session.kcp, s[7:], _len)
							//log.Println("direct input udp", id, seq, _len)
						}
						if seq >= uint(session.fecDataShards+session.fecParityShards) {
							log.Println("-ds and -ps must be equal on both sides")
							go session.Close()
							break
						}

						tbl, have := session.fecRCacheTbl[id]
						if !have {
							tbl = &fecInfo{make([][]byte, session.fecDataShards+session.fecParityShards), time.Now().Unix() + 3}
							session.fecRCacheTbl[id] = tbl
						}
						//log.Println("got", id, seq, n, _len)
						if tbl.bytes[seq] != nil {
							//dup, drop
							break
						} else {
							tbl.bytes[seq] = s[7:7+_len]
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
						if count >= session.fecDataShards {
							markTbl := make(map[int]bool, len(tbl.bytes))
							bNeedRebuild := false
							for _seq, _b := range tbl.bytes {
								if _b != nil {
									markTbl[_seq] = true
								} else if _seq < session.fecDataShards {
									bNeedRebuild = true
								}
							}

							if bNeedRebuild {
								mapLen := make(map[int]int)
								for i, v := range tbl.bytes {
									if v != nil {
										if len(v) < reaL {
											mapLen[i]= len(v)
											_b := make([]byte, reaL)
											copy(_b, v)
											tbl.bytes[i] = _b
										}
									}
								}
								er := (*session.fecR).Reconstruct(tbl.bytes)
								if er != nil {
									//log.Println("2Reconstruct fail, close pipe", count, session.fecDataShards, session.fecParityShards, er.Error())
									//break //broken data, may be should be closed, now just keep input
								} else {
									//log.Println("Reconstruct ok, input", id)
									for i := 0; i < session.fecDataShards; i++ {
										if _, have := markTbl[i]; !have {
											_len := mapLen[i]
											ikcp.Ikcp_input(session.kcp, tbl.bytes[i][:_len], _len)
											//log.Println("fec input for mark ok", i, id, _len)
										}
									}
								}
							}
							delete(session.fecRCacheTbl, id)
							//log.Println("after del", id, len(session.fecRCacheTbl))
						}
					} else {
						if n < 7 {
							log.Println("recv reset")
							go session._Close(false)
							break
						} else if n == 7 {
							status, _, _ := makeDecode(s, session.xor)
							if status == Reset || status == ResetAck {
								log.Println("recv reset2", status)
								go session._Close(false)
							}
							break
						}
						ikcp.Ikcp_input(session.kcp, s, n)
					}

					if waitRecvCache != nil {
						ca := *waitRecvCache
						tmp := session.processBuffer
						for {
							hr := ikcp.Ikcp_recv(session.kcp, tmp, ReadBufferSize)
							if hr > 0 {
								status := tmp[0]
								if status == Data {
									n := 1
									l := hr
									if session.confuseSeed > 0 {
										n = 3
										l = (int32(tmp[1]) | (int32(tmp[2]) << 8)) + int32(n)
									}
									//log.Println("try recv", n, l)
									waitRecvCache = nil
									copy(ca.b, tmp[n:int(l)])
									select {
									case ca.c <- (int(l) - n):
									case <-session.quitChan:
									}
									break
								} else if status == Fake {
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
	case ping <- struct{}{}:
	case <-session.quitChan:
	}
	out:
	for {
		select {
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
				buf := make([]byte, 7)
				go session.DoWrite(makeEncode(buf, Close, 0, 0, session.xor))
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
						buf := make([]byte, 7)
						go session.DoWrite(makeEncode(buf, CloseBack, 0, 0, session.xor))
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
			if session.sock != nil {
				session.sock.Close()
			}
		}
	}()
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
	wc := make(chan struct{})
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
	var data []byte
	if session.confuseSeed <= 0 {
		data = make([]byte, sendL+1)
		data[0] = Data
		copy(data[1:], b)
	} else {
		remain := WriteBufferSize - sendL - 3
		if remain > 0 && (WriteBufferSize/2-rand.Intn(session.confuseSeed) < 500 || rand.Intn(100) < 5) {
			if remain > 1000 {
				remain = 1000
			}
			remain = rand.Intn(remain / 2)
		} else {
			remain = 0
		}
		data = make([]byte, sendL+remain+3)
		data[0] = Data
		data[1] = byte(sendL & 0xff)
		data[2] = byte((sendL >> 8) & 0xff)
		copy(data[3:], b)
		//log.Println("try send", len(data), sendL)
		//copy(data[3+sendL:], b)
	}
	ok := session.DoWrite(data)
	if !ok {
		return 0, errors.New("closed")
	}
	if session.confuseSeed > 0 {
		if rand.Intn(WriteBufferSize/2) > session.confuseSeed/2 {
			n := rand.Intn(session.confuseSeed)
			if n > 10 {
				d := make([]byte, n)
				d[0] = Fake
				session.DoWrite(d)
			}
		}
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
	//log.Println("real recv", l, string(b[:l]))
	if n == -1 {
		return 0, errors.New("force quit for read error")
	} else {
		return n, nil
	}
}
