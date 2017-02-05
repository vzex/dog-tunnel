package ikcp

import "container/list"
import "encoding/binary"

//=====================================================================
//
// KCP - A Better ARQ Protocol Implementation
// skywind3000 (at) gmail.com, 2010-2011
//
// Features:
// + Average RTT reduce 30% - 40% vs traditional ARQ like tcp.
// + Maximum RTT reduce three times vs tcp.
// + Lightweight, distributed as a single source file.
//
//=====================================================================

//=====================================================================
// KCP BASIC
//=====================================================================
const IKCP_RTO_NDL uint32 = 30  // no delay min rto
const IKCP_RTO_MIN uint32 = 100 // normal min rto
const IKCP_RTO_DEF uint32 = 200
const IKCP_RTO_MAX uint32 = 60000
const IKCP_CMD_PUSH uint32 = 81 // cmd: push data
const IKCP_CMD_ACK uint32 = 82  // cmd: ack
const IKCP_CMD_WASK uint32 = 83 // cmd: window probe (ask)
const IKCP_CMD_WINS uint32 = 84 // cmd: window size (tell)
const IKCP_ASK_SEND uint32 = 1  // need to send IKCP_CMD_WASK
const IKCP_ASK_TELL uint32 = 2  // need to send IKCP_CMD_WINS
const IKCP_WND_SND uint32 = 32
const IKCP_WND_RCV uint32 = 32
const IKCP_MTU_DEF uint32 = 1400
const IKCP_ACK_FAST uint32 = 3
const IKCP_INTERVAL uint32 = 100
const IKCP_OVERHEAD uint32 = 24
const IKCP_DEADLINK uint32 = 10
const IKCP_THRESH_INIT uint32 = 2
const IKCP_THRESH_MIN uint32 = 2
const IKCP_PROBE_INIT uint32 = 7000    // 7 secs to probe window size
const IKCP_PROBE_LIMIT uint32 = 120000 // up to 120 secs to probe window

//---------------------------------------------------------------------
// encode / decode
//---------------------------------------------------------------------

/* encode 8 bits unsigned int */
func ikcp_encode8u(p []byte, c byte) []byte {
	p[0] = c
	return p[1:]
}

/* decode 8 bits unsigned int */
func ikcp_decode8u(p []byte, c *byte) []byte {
	*c = p[0]
	return p[1:]
}

/* encode 16 bits unsigned int (lsb) */
func ikcp_encode16u(p []byte, w uint16) []byte {
	binary.LittleEndian.PutUint16(p, w)
	return p[2:]
}

/* decode 16 bits unsigned int (lsb) */
func ikcp_decode16u(p []byte, w *uint16) []byte {
	*w = binary.LittleEndian.Uint16(p)
	return p[2:]
}

/* encode 32 bits unsigned int (lsb) */
func ikcp_encode32u(p []byte, l uint32) []byte {
	binary.LittleEndian.PutUint32(p, l)
	return p[4:]
}

/* decode 32 bits unsigned int (lsb) */
func ikcp_decode32u(p []byte, l *uint32) []byte {
	*l = binary.LittleEndian.Uint32(p)
	return p[4:]
}

func _imin_(a, b uint32) uint32 {
	if a <= b {
		return a
	} else {
		return b
	}
}

func _imax_(a, b uint32) uint32 {
	if a >= b {
		return a
	} else {
		return b
	}
}

func _ibound_(lower, middle, upper uint32) uint32 {
	return _imin_(_imax_(lower, middle), upper)
}

func _itimediff(later, earlier uint32) int32 {
	return ((int32)(later - earlier))
}

//---------------------------------------------------------------------
// manage segment
//---------------------------------------------------------------------
type IKCPSEG struct {
	conv     uint32
	cmd      uint32
	frg      uint32
	wnd      uint32
	ts       uint32
	sn       uint32
	una      uint32
	_len     uint32
	resendts uint32
	rto      uint32
	fastack  uint32
	xmit     uint32
	data     []byte //1 size
}

/*
static void* (*ikcp_malloc_hook)(size_t) = nil
static void (*ikcp_free_hook)(void *) = nil

// internal malloc
static void* ikcp_malloc(size_t size) {
        if (ikcp_malloc_hook)
        return ikcp_malloc_hook(size)
        return malloc(size)
}

// internal free
static void ikcp_free(void *ptr) {
        if (ikcp_free_hook) {
                ikcp_free_hook(ptr)
        }	else {
                free(ptr)
        }
}
// redefine allocator
void ikcp_allocator(void* (*new_malloc)(size_t), void (*new_free)(void*))
{
        ikcp_malloc_hook = new_malloc
        ikcp_free_hook = new_free
}

// allocate a new kcp segment
*/
func ikcp_segment_new(kcp *Ikcpcb, size int32) *IKCPSEG {
	newInfo := &IKCPSEG{}
	newInfo.data = make([]byte, size)
	return newInfo
}

// delete a segment

// write log
func Ikcp_log(kcp *Ikcpcb, mask int32, head string, args ...interface{}) {
	//if ((mask & kcp.logmask) == 0 || kcp.writelog == 0) { return }
	//fmt.Printf(head, args...)
}

// check log mask
func ikcp_canlog(kcp *Ikcpcb, mask int32) int32 {
	if (mask&kcp.logmask) == 0 || kcp.writelog == nil {
		return 0
	}
	return 1
}

// output segment
func ikcp_output(kcp *Ikcpcb, data []byte, size int32) int32 {
	if ikcp_canlog(kcp, IKCP_LOG_OUTPUT) != 0 {
		Ikcp_log(kcp, IKCP_LOG_OUTPUT, "[RO] %ld bytes", int32(size))
	}
	if size == 0 {
		return 0
	}
	return kcp.Output(data, size, kcp, kcp.user)
}

//---------------------------------------------------------------------
// create a new kcpcb
//---------------------------------------------------------------------
func Ikcp_create(conv uint32, user interface{}) *Ikcpcb {
	kcp := &Ikcpcb{}
	kcp.conv = conv
	kcp.user = user
	kcp.snd_una = 0
	kcp.snd_nxt = 0
	kcp.rcv_nxt = 0
	kcp.ts_recent = 0
	kcp.ts_lastack = 0
	kcp.ts_probe = 0
	kcp.probe_wait = 0
	kcp.snd_wnd = IKCP_WND_SND
	kcp.rcv_wnd = IKCP_WND_RCV
	kcp.rmt_wnd = IKCP_WND_RCV
	kcp.cwnd = 0
	kcp.incr = 0
	kcp.probe = 0
	kcp.mtu = IKCP_MTU_DEF
	kcp.mss = kcp.mtu - IKCP_OVERHEAD

	kcp.buffer = make([]byte, (kcp.mtu+IKCP_OVERHEAD)*3)
	if kcp.buffer == nil {
		return nil
	}

	kcp.snd_queue = list.New()
	kcp.rcv_queue = list.New()
	kcp.snd_buf = list.New()
	kcp.rcv_buf = list.New()
	kcp.nrcv_buf = 0
	kcp.nsnd_buf = 0
	kcp.nrcv_que = 0
	kcp.nsnd_que = 0
	kcp.state = 0
	kcp.acklist = nil
	kcp.ackblock = 0
	kcp.ackcount = 0
	kcp.rx_srtt = 0
	kcp.rx_rttval = 0
	kcp.rx_rto = IKCP_RTO_DEF
	kcp.rx_minrto = IKCP_RTO_MIN
	kcp.current = 0
	kcp.interval = IKCP_INTERVAL
	kcp.ts_flush = IKCP_INTERVAL
	kcp.nodelay = 0
	kcp.updated = 0
	kcp.logmask = 0
	kcp.ssthresh = IKCP_THRESH_INIT
	kcp.fastresend = 0
	kcp.nocwnd = 0
	kcp.xmit = 0
	kcp.dead_link = IKCP_DEADLINK
	kcp.Output = nil
	kcp.writelog = nil

	return kcp
}

//---------------------------------------------------------------------
// release a new kcpcb
//---------------------------------------------------------------------
func Ikcp_release(kcp *Ikcpcb) {
	if kcp != nil {
		kcp.nrcv_buf = 0
		kcp.nsnd_buf = 0
		kcp.nrcv_que = 0
		kcp.nsnd_que = 0
		kcp.ackcount = 0
		kcp.buffer = nil
		kcp.acklist = nil
	}
}

//---------------------------------------------------------------------
// recv data
//---------------------------------------------------------------------
func Ikcp_recv(kcp *Ikcpcb, buffer []byte, _len int32) int32 {
	ispeek := 1
	if _len >= 0 {
		ispeek = 0
	}
	var peeksize int32
	_recover := 0
	var seg *IKCPSEG

	if kcp.rcv_queue.Len() == 0 {
		return -1
	}

	if _len < 0 {
		_len = -_len
	}

	peeksize = Ikcp_peeksize(kcp)

	if peeksize < 0 {
		return -2
	}

	if peeksize > _len {
		return -3
	}

	if kcp.nrcv_que >= kcp.rcv_wnd {
		_recover = 1
	}

	//if kcp.user[0] == 0 {
	//fmt.Println("have!!!!")
	//}
	// merge fragment
	_len = 0
	for p := kcp.rcv_queue.Front(); p != nil; {
		var fragment int32
		seg = p.Value.(*IKCPSEG)

		if len(buffer) > 0 {
			copy(buffer, seg.data[:seg._len])
			buffer = buffer[seg._len:]
		}

		_len += int32(seg._len)
		fragment = int32(seg.frg)

		if ikcp_canlog(kcp, IKCP_LOG_RECV) != 0 {
			Ikcp_log(kcp, IKCP_LOG_RECV, "recv sn=", seg.sn, seg._len, kcp.user)
		}

		if ispeek == 0 {
			q := p.Next()
			kcp.rcv_queue.Remove(p)
			p = q
			kcp.nrcv_que--
			//if kcp.user[0] == 0 {
			//fmt.Println("remove from recvqueue", kcp.rcv_queue.Len(), kcp.user, "rcv q:", kcp.nrcv_que)
			//}
		} else {
			p = p.Next()
		}

		if fragment == 0 {
			break
		}
	}
	// move available data from rcv_buf . rcv_queue
	for p := kcp.rcv_buf.Front(); p != nil; {
		seg := p.Value.(*IKCPSEG)
		if seg.sn == kcp.rcv_nxt && kcp.nrcv_que < kcp.rcv_wnd {
			q := p.Next()
			kcp.rcv_buf.Remove(p)
			p = q
			kcp.nrcv_buf--
			kcp.rcv_queue.PushBack(seg)
			kcp.nrcv_que++
			//if kcp.user[0] == 0 {
			//fmt.Println("insert from recvqueue", kcp.rcv_queue.Len(), kcp.user, "rcv q:", kcp.nrcv_que)
			//}
			kcp.rcv_nxt++
		} else {
			break
		}
	}

	// fast _recover
	if kcp.nrcv_que < kcp.rcv_wnd && _recover != 0 {
		// ready to send back IKCP_CMD_WINS in Ikcp_flush
		// tell remote my window size
		kcp.probe |= IKCP_ASK_TELL
	}

	return _len
}

//---------------------------------------------------------------------
// send data
//---------------------------------------------------------------------
func Ikcp_peeksize(kcp *Ikcpcb) int32 {
	length := 0

	if kcp.rcv_queue.Len() == 0 {
		return -1
	}

	seg := kcp.rcv_queue.Front().Value.(*IKCPSEG)
	if seg.frg == 0 {
		return int32(seg._len)
	}

	if kcp.nrcv_que < seg.frg+1 {
		return -1
	}

	for p := kcp.rcv_queue.Front(); p != nil; p = p.Next() {
		seg = p.Value.(*IKCPSEG)
		length += int(seg._len)
		if seg.frg == 0 {
			break
		}
	}

	return int32(length)
}

//---------------------------------------------------------------------
// send data
//---------------------------------------------------------------------
func Ikcp_send(kcp *Ikcpcb, buffer []byte, _len int) int {
	var seg *IKCPSEG
	var count, i int32

	if _len < 0 {
		return -1
	}

	if _len <= int(kcp.mss) {
		count = 1
	} else {
		count = (int32(_len) + int32(kcp.mss) - 1) / int32(kcp.mss)
	}

	if count > 255 {
		return -2
	}

	if count == 0 {
		count = 1
	}

	// fragment
	for i = 0; i < count; i++ {
		size := int32(kcp.mss)
		if _len <= int(kcp.mss) {
			size = int32(_len)
		}
		seg = ikcp_segment_new(kcp, size)
		if seg == nil {
			return -2
		}
		if buffer != nil && _len > 0 {
			copy(seg.data, buffer[:size])
		}
		seg._len = uint32(size)
		seg.frg = uint32(count - i - 1)
		kcp.snd_queue.PushBack(seg)
		//if kcp.user[0] == 0 {
		//fmt.Println(kcp.user, "send", kcp.snd_queue.Len())
		//}
		kcp.nsnd_que++
		if buffer != nil {
			buffer = buffer[size:]
		}
		_len -= int(size)
	}

	return 0
}

//---------------------------------------------------------------------
// parse ack
//---------------------------------------------------------------------
func Ikcp_update_ack(kcp *Ikcpcb, rtt int32) {
	rto := 0
	if kcp.rx_srtt == 0 {
		kcp.rx_srtt = uint32(rtt)
		kcp.rx_rttval = uint32(rtt) / 2
	} else {
		delta := rtt - int32(kcp.rx_srtt)
		if delta < 0 {
			delta = -delta
		}
		kcp.rx_rttval = (3*kcp.rx_rttval + uint32(delta)) / 4
		kcp.rx_srtt = (7*kcp.rx_srtt + uint32(rtt)) / 8
		if kcp.rx_srtt < 1 {
			kcp.rx_srtt = 1
		}
	}
	rto = int(kcp.rx_srtt + _imax_(kcp.interval, 4*kcp.rx_rttval))
	kcp.rx_rto = _ibound_(kcp.rx_minrto, uint32(rto), IKCP_RTO_MAX)
}

func ikcp_shrink_buf(kcp *Ikcpcb) {
	if kcp.snd_buf.Len() > 0 {
		p := kcp.snd_buf.Front()
		seg := p.Value.(*IKCPSEG)
		kcp.snd_una = seg.sn
		//if kcp.user[0] == 0 {
		//println("set snd_una:", seg.sn)
		//}
	} else {
		kcp.snd_una = kcp.snd_nxt
		//if kcp.user[0] == 0 {
		//println("set2 snd_una:", kcp.snd_nxt)
		//}
	}
}

func ikcp_parse_ack(kcp *Ikcpcb, sn uint32) {
	if _itimediff(sn, kcp.snd_una) < 0 || _itimediff(sn, kcp.snd_nxt) >= 0 {
		//        //fmt.Printf("wi %d,%d  %d,%d\n", sn, kcp.snd_una, sn, kcp.snd_nxt)
		return
	}

	for p := kcp.snd_buf.Front(); p != nil; p = p.Next() {
		seg := p.Value.(*IKCPSEG)
		if sn == seg.sn {
			kcp.snd_buf.Remove(p)
			kcp.nsnd_buf--
			break
		}
		if _itimediff(sn, seg.sn) < 0 {
			break
		}
	}
}

func ikcp_parse_fastack(kcp *Ikcpcb, sn uint32) {
	if _itimediff(sn, kcp.snd_una) < 0 || _itimediff(sn, kcp.snd_nxt) >= 0 {
		return
	}

	for p := kcp.snd_buf.Front(); p != nil; p = p.Next() {
		seg := p.Value.(*IKCPSEG)
		if _itimediff(sn, seg.sn) < 0 {
			break
		} else if sn != seg.sn {
			seg.fastack++
		}
	}
}

func ikcp_parse_una(kcp *Ikcpcb, una uint32) {
	for p := kcp.snd_buf.Front(); p != nil; {
		seg := p.Value.(*IKCPSEG)
		if _itimediff(una, seg.sn) > 0 {
			q := p.Next()
			kcp.snd_buf.Remove(p)
			p = q
			kcp.nsnd_buf--
		} else {
			break
		}
	}
}

//---------------------------------------------------------------------
// ack append
//---------------------------------------------------------------------
func ikcp_ack_push(kcp *Ikcpcb, sn, ts uint32) {
	newsize := kcp.ackcount + 1

	if newsize > kcp.ackblock {
		var acklist []uint32
		var newblock int32

		for newblock = 8; uint32(newblock) < newsize; newblock <<= 1 {
		}
		acklist = make([]uint32, newblock*2)
		if kcp.acklist != nil {
			for x := 0; uint32(x) < kcp.ackcount; x++ {
				acklist[x*2+0] = kcp.acklist[x*2+0]
				acklist[x*2+1] = kcp.acklist[x*2+1]
			}
		}
		kcp.acklist = acklist
		kcp.ackblock = uint32(newblock)
	}

	ptr := kcp.acklist[kcp.ackcount*2:]
	ptr[0] = sn
	ptr[1] = ts
	kcp.ackcount++
}

func ikcp_ack_get(kcp *Ikcpcb, p int32, sn, ts *uint32) {
	if sn != nil {
		*sn = kcp.acklist[p*2+0]
	}
	if ts != nil {
		*ts = kcp.acklist[p*2+1]
	}
}

//---------------------------------------------------------------------
// parse data
//---------------------------------------------------------------------
func ikcp_parse_data(kcp *Ikcpcb, newseg *IKCPSEG) {
	var p *list.Element
	sn := newseg.sn
	repeat := 0
	if _itimediff(sn, kcp.rcv_nxt+kcp.rcv_wnd) >= 0 ||
		_itimediff(sn, kcp.rcv_nxt) < 0 {
		return
	}

	for p = kcp.rcv_buf.Back(); p != nil; p = p.Prev() {
		seg := p.Value.(*IKCPSEG)
		if seg.sn == sn {
			repeat = 1
			break
		}
		if _itimediff(sn, seg.sn) > 0 {
			break
		}
	}

	if repeat == 0 {
		if p == nil {
			kcp.rcv_buf.PushFront(newseg)
		} else {
			kcp.rcv_buf.InsertAfter(newseg, p)
		}
		kcp.nrcv_buf++
	} else {
	}
	for p = kcp.rcv_buf.Front(); p != nil; {
		seg := p.Value.(*IKCPSEG)
		if seg.sn == kcp.rcv_nxt && kcp.nrcv_que < kcp.rcv_wnd {
			q := p.Next()
			kcp.rcv_buf.Remove(p)
			p = q
			kcp.nrcv_buf--
			kcp.rcv_queue.PushBack(seg)
			//if kcp.user[0] == 0 {
			//fmt.Println("insert from recvqueue2", kcp.rcv_queue.Len(), kcp.user)
			//}
			kcp.nrcv_que++
			kcp.rcv_nxt++
		} else {
			break
		}
	}
	//println("inputok!!!", kcp.nrcv_buf, kcp.nrcv_que, repeat, kcp.rcv_nxt, sn)
}

//---------------------------------------------------------------------
// input data
//---------------------------------------------------------------------
func Ikcp_input(kcp *Ikcpcb, data []byte, size int) int {
	una := kcp.snd_una
	var maxack uint32 = 0
	flag := 0
	if ikcp_canlog(kcp, IKCP_LOG_INPUT) != 0 {
		Ikcp_log(kcp, IKCP_LOG_INPUT, "[RI] %d bytes", size)
	}

	if data == nil || size < 24 {
		return 0
	}

	for {
		var ts, sn, _len, una, conv uint32
		var wnd uint16
		var cmd, frg uint8
		var seg *IKCPSEG

		if size < int(IKCP_OVERHEAD) {
			break
		}

		data = ikcp_decode32u(data, &conv)
		if conv != kcp.conv {
			return -1
		}

		data = ikcp_decode8u(data, &cmd)
		data = ikcp_decode8u(data, &frg)
		data = ikcp_decode16u(data, &wnd)
		data = ikcp_decode32u(data, &ts)
		data = ikcp_decode32u(data, &sn)
		data = ikcp_decode32u(data, &una)
		data = ikcp_decode32u(data, &_len)

		size -= int(IKCP_OVERHEAD)

		if uint32(size) < uint32(_len) {
			return -2
		}

		if cmd != uint8(IKCP_CMD_PUSH) && cmd != uint8(IKCP_CMD_ACK) &&
			cmd != uint8(IKCP_CMD_WASK) && cmd != uint8(IKCP_CMD_WINS) {
			return -3
		}

		kcp.rmt_wnd = uint32(wnd)
		ikcp_parse_una(kcp, una)
		ikcp_shrink_buf(kcp)

		if cmd == uint8(IKCP_CMD_ACK) {
			if _itimediff(kcp.current, ts) >= 0 {
				Ikcp_update_ack(kcp, _itimediff(kcp.current, ts))
			}
			ikcp_parse_ack(kcp, sn)
			ikcp_shrink_buf(kcp)
			if flag == 0 {
				flag = 1
				maxack = sn
			} else {
				if _itimediff(sn, maxack) > 0 {
					maxack = sn
				}
			}
			/*
			   log.Printf(
			   "input ack: sn=%lu rtt=%ld rto=%ld", sn,
			   uint32(_itimediff(kcp.current, ts)),
			   uint32(kcp.rx_rto))*/
		} else if cmd == uint8(IKCP_CMD_PUSH) {
			/*
			   log.Printf(
			   "input psh: sn=%lu ts=%lu", sn, ts)*/
			if _itimediff(sn, kcp.rcv_nxt+kcp.rcv_wnd) < 0 {
				ikcp_ack_push(kcp, sn, ts)
				if _itimediff(sn, kcp.rcv_nxt) >= 0 {
					seg = ikcp_segment_new(kcp, int32(_len))
					seg.conv = conv
					seg.cmd = uint32(cmd)
					seg.frg = uint32(frg)
					seg.wnd = uint32(wnd)
					seg.ts = ts
					seg.sn = sn
					seg.una = una
					seg._len = _len

					if _len > 0 {
						copy(seg.data, data[:_len])
					}

					ikcp_parse_data(kcp, seg)
				}
			}
		} else if cmd == uint8(IKCP_CMD_WASK) {
			// ready to send back IKCP_CMD_WINS in Ikcp_flush
			// tell remote my window size
			kcp.probe |= IKCP_ASK_TELL
			if ikcp_canlog(kcp, IKCP_LOG_IN_PROBE) != 0 {
				Ikcp_log(kcp, IKCP_LOG_IN_PROBE, "input probe")
			}
		} else if cmd == uint8(IKCP_CMD_WINS) {
			// do nothing
			if ikcp_canlog(kcp, IKCP_LOG_IN_WIN) != 0 {
				Ikcp_log(kcp, IKCP_LOG_IN_WIN,
					"input wins: %lu", uint32(wnd))
			}
		} else {
			return -3
		}

		data = data[_len:]
		size -= int(_len)
	}

	if flag != 0 {
		ikcp_parse_fastack(kcp, maxack)
	}

	if _itimediff(kcp.snd_una, una) > 0 {
		if kcp.cwnd < kcp.rmt_wnd {
			mss := kcp.mss
			if kcp.cwnd < kcp.ssthresh {
				kcp.cwnd++
				kcp.incr += mss
			} else {
				if kcp.incr < mss {
					kcp.incr = mss
				}
				kcp.incr += (mss*mss)/kcp.incr + (mss / 16)
				if (kcp.cwnd+1)*mss <= kcp.incr {
					kcp.cwnd++
				}
			}
			if kcp.cwnd > kcp.rmt_wnd {
				kcp.cwnd = kcp.rmt_wnd
				kcp.incr = kcp.rmt_wnd * mss
			}
		}
	}

	return 0
}

//---------------------------------------------------------------------
// ikcp_encode_seg
//---------------------------------------------------------------------
func ikcp_encode_seg(ptr []byte, seg *IKCPSEG) []byte {
	ptr = ikcp_encode32u(ptr, seg.conv)
	ptr = ikcp_encode8u(ptr, uint8(seg.cmd))
	ptr = ikcp_encode8u(ptr, uint8(seg.frg))
	ptr = ikcp_encode16u(ptr, uint16(seg.wnd))
	ptr = ikcp_encode32u(ptr, seg.ts)
	ptr = ikcp_encode32u(ptr, seg.sn)
	ptr = ikcp_encode32u(ptr, seg.una)
	ptr = ikcp_encode32u(ptr, seg._len)
	return ptr
}

func ikcp_wnd_unused(kcp *Ikcpcb) int32 {
	if kcp.nrcv_que < kcp.rcv_wnd {
		return int32(kcp.rcv_wnd - kcp.nrcv_que)
	}
	return 0
}

//---------------------------------------------------------------------
// Ikcp_flush
//---------------------------------------------------------------------
func Ikcp_flush(kcp *Ikcpcb) {
	current := kcp.current
	buffer := kcp.buffer
	ptr := buffer
	var count, size, i int32
	var resent, cwnd uint32
	var rtomin uint32
	change := 0
	lost := 0
	var seg IKCPSEG

	// 'Ikcp_update' haven't been called.
	if kcp.updated == 0 {
		return
	}

	seg.conv = kcp.conv
	seg.cmd = IKCP_CMD_ACK
	seg.frg = 0
	seg.wnd = uint32(ikcp_wnd_unused(kcp))
	seg.una = kcp.rcv_nxt
	seg._len = 0
	seg.sn = 0
	seg.ts = 0

	// flush acknowledges
	size = 0
	count = int32(kcp.ackcount)
	for i = 0; i < count; i++ {
		//size = int32(ptr - buffer)
		if size+int32(IKCP_OVERHEAD) > int32(kcp.mtu) {
			ikcp_output(kcp, buffer, size)
			ptr = buffer
			size = 0
		}
		ikcp_ack_get(kcp, i, &seg.sn, &seg.ts)
		ptr = ikcp_encode_seg(ptr, &seg)
		size += 24
	}

	kcp.ackcount = 0

	// probe window size (if remote window size equals zero)
	if kcp.rmt_wnd == 0 {
		if kcp.probe_wait == 0 {
			kcp.probe_wait = IKCP_PROBE_INIT
			kcp.ts_probe = kcp.current + kcp.probe_wait
		} else {
			if _itimediff(kcp.current, kcp.ts_probe) >= 0 {
				if kcp.probe_wait < IKCP_PROBE_INIT {
					kcp.probe_wait = IKCP_PROBE_INIT
				}
				kcp.probe_wait += kcp.probe_wait / 2
				if kcp.probe_wait > IKCP_PROBE_LIMIT {
					kcp.probe_wait = IKCP_PROBE_LIMIT
				}
				kcp.ts_probe = kcp.current + kcp.probe_wait
				kcp.probe |= IKCP_ASK_SEND
			}
		}
	} else {
		kcp.ts_probe = 0
		kcp.probe_wait = 0
	}

	// flush window probing commands
	if (kcp.probe & IKCP_ASK_SEND) != 0 {
		seg.cmd = IKCP_CMD_WASK
		if size+int32(IKCP_OVERHEAD) > int32(kcp.mtu) {
			ikcp_output(kcp, buffer, size)
			ptr = buffer
			size = 0
		}
		ptr = ikcp_encode_seg(ptr, &seg)
		size += 24
	}

	// flush window probing commands
	if (kcp.probe & IKCP_ASK_TELL) != 0 {
		seg.cmd = IKCP_CMD_WINS
		if size+int32(IKCP_OVERHEAD) > int32(kcp.mtu) {
			ikcp_output(kcp, buffer, size)
			ptr = buffer
			size = 0
		}
		ptr = ikcp_encode_seg(ptr, &seg)
		size += 24
	}

	kcp.probe = 0

	// calculate window size
	cwnd = _imin_(kcp.snd_wnd, kcp.rmt_wnd)
	if kcp.nocwnd == 0 {
		cwnd = _imin_(kcp.cwnd, cwnd)
	}

	// move data from snd_queue to snd_buf
	////println("check",kcp.snd_queue.Len())
	for p := kcp.snd_queue.Front(); p != nil; {
		////println("debug check:", t, p.Next(), kcp.snd_nxt, kcp.snd_una, cwnd, _itimediff(kcp.snd_nxt, kcp.snd_una + cwnd))
		////fmt.Printf("timediff %d,%d,%d,%d\n", kcp.snd_nxt, kcp.snd_una, cwnd, _itimediff(kcp.snd_nxt, kcp.snd_una + cwnd));
		if _itimediff(kcp.snd_nxt, kcp.snd_una+cwnd) >= 0 {
			//if kcp.user[0] == 0 {
			////fmt.Println("=======", kcp.snd_nxt, kcp.snd_una, cwnd)
			//}
			break
		}
		newseg := p.Value.(*IKCPSEG)
		q := p.Next()
		kcp.snd_queue.Remove(p)
		p = q
		kcp.snd_buf.PushBack(newseg)
		//if kcp.user[0] == 0 {
		//println("debug check2:", t, kcp.snd_queue.Len(), kcp.snd_buf.Len(), kcp.nsnd_que)
		//}
		kcp.nsnd_que--
		kcp.nsnd_buf++

		newseg.conv = kcp.conv
		newseg.cmd = IKCP_CMD_PUSH
		newseg.wnd = seg.wnd
		newseg.ts = current
		newseg.sn = kcp.snd_nxt
		kcp.snd_nxt++
		newseg.una = kcp.rcv_nxt
		newseg.resendts = current
		newseg.rto = kcp.rx_rto
		newseg.fastack = 0
		newseg.xmit = 0
	}

	// calculate resent
	resent = uint32(kcp.fastresend)
	if kcp.fastresend <= 0 {
		resent = 0xffffffff
	}
	rtomin = (kcp.rx_rto >> 3)
	if kcp.nodelay != 0 {
		rtomin = 0
	}

	// flush data segments
	for p := kcp.snd_buf.Front(); p != nil; p = p.Next() {
		////println("debug loop", a, kcp.snd_buf.Len())
		segment := p.Value.(*IKCPSEG)
		needsend := 0
		if segment.xmit == 0 {
			needsend = 1
			segment.xmit++
			segment.rto = kcp.rx_rto
			segment.resendts = current + segment.rto + rtomin
		} else if _itimediff(current, segment.resendts) >= 0 {
			needsend = 1
			segment.xmit++
			kcp.xmit++
			if kcp.nodelay == 0 {
				segment.rto += kcp.rx_rto
			} else {
				segment.rto += kcp.rx_rto / 2
			}
			segment.resendts = current + segment.rto
			lost = 1
		} else if segment.fastack >= resent {
			needsend = 1
			segment.xmit++
			segment.fastack = 0
			segment.resendts = current + segment.rto
			change++
		}
		if needsend != 0 {
			var need int32
			segment.ts = current
			segment.wnd = seg.wnd
			segment.una = kcp.rcv_nxt

			need = int32(IKCP_OVERHEAD + segment._len)

			////fmt.Printf("vzex:need send%d, %d,%d,%d\n", kcp.nsnd_buf, size, need, kcp.mtu)
			if size+need > int32(kcp.mtu) {
				//      //fmt.Printf("trigger!\n");
				ikcp_output(kcp, buffer, size)
				ptr = buffer
				size = 0
			}

			ptr = ikcp_encode_seg(ptr, segment)
			size += 24

			if segment._len > 0 {
				copy(ptr, segment.data[:segment._len])
				ptr = ptr[segment._len:]
				size += int32(segment._len)
			}

			if segment.xmit >= kcp.dead_link {
				kcp.state = 0
			}
		}
	}

	// flash remain segments
	if size > 0 {
		ikcp_output(kcp, buffer, size)
	}

	// update ssthresh
	if change != 0 {
		inflight := kcp.snd_nxt - kcp.snd_una
		kcp.ssthresh = inflight / 2
		if kcp.ssthresh < IKCP_THRESH_MIN {
			kcp.ssthresh = IKCP_THRESH_MIN
		}
		kcp.cwnd = kcp.ssthresh + resent
		kcp.incr = kcp.cwnd * kcp.mss
	}

	if lost != 0 {
		kcp.ssthresh = cwnd / 2
		if kcp.ssthresh < IKCP_THRESH_MIN {
			kcp.ssthresh = IKCP_THRESH_MIN
		}
		kcp.cwnd = 1
		kcp.incr = kcp.mss
	}

	if kcp.cwnd < 1 {
		kcp.cwnd = 1
		kcp.incr = kcp.mss
	}
}

//---------------------------------------------------------------------
// input update
//---------------------------------------------------------------------
func Ikcp_update(kcp *Ikcpcb, current uint32) {
	var slap int32

	kcp.current = current

	if kcp.updated == 0 {
		kcp.updated = 1
		kcp.ts_flush = kcp.current
	}

	slap = _itimediff(kcp.current, kcp.ts_flush)

	if slap >= 10000 || slap < -10000 {
		kcp.ts_flush = kcp.current
		slap = 0
	}

	if slap >= 0 {
		kcp.ts_flush += kcp.interval
		if _itimediff(kcp.current, kcp.ts_flush) >= 0 {
			kcp.ts_flush = kcp.current + kcp.interval
		}
		Ikcp_flush(kcp)
	}
}

func Ikcp_check(kcp *Ikcpcb, current uint32) uint32 {
	ts_flush := kcp.ts_flush
	tm_flush := 0x7fffffff
	tm_packet := 0x7fffffff
	minimal := 0
	if kcp.updated == 0 {
		return current
	}

	if _itimediff(current, ts_flush) >= 10000 ||
		_itimediff(current, ts_flush) < -10000 {
		ts_flush = current
	}

	if _itimediff(current, ts_flush) >= 0 {
		return current
	}

	tm_flush = int(_itimediff(ts_flush, current))

	for p := kcp.snd_buf.Front(); p != nil; p = p.Next() {
		seg := p.Value.(*IKCPSEG)
		diff := _itimediff(seg.resendts, current)
		if diff <= 0 {
			return current
		}
		if diff < int32(tm_packet) {
			tm_packet = int(diff)
		}
	}

	minimal = int(tm_packet)
	if tm_packet >= tm_flush {
		minimal = int(tm_flush)
	}
	if uint32(minimal) >= kcp.interval {
		minimal = int(kcp.interval)
	}

	return current + uint32(minimal)
}

func Ikcp_setmtu(kcp *Ikcpcb, mtu int32) int32 {
	if mtu < 50 || mtu < int32(IKCP_OVERHEAD) {
		return -1
	}
	buffer := make([]byte, (uint32(mtu)+IKCP_OVERHEAD)*3)
	if buffer == nil {
		return -2
	}
	kcp.mtu = uint32(mtu)
	kcp.mss = kcp.mtu - IKCP_OVERHEAD
	kcp.buffer = buffer
	return 0
}

func ikcp_interval(kcp *Ikcpcb, interval int32) int32 {
	if interval > 5000 {
		interval = 5000
	} else if interval < 10 {
		interval = 10
	}
	kcp.interval = uint32(interval)
	return 0
}

func Ikcp_nodelay(kcp *Ikcpcb, nodelay, interval, resend, nc int32) int32 {
	if nodelay >= 0 {
		kcp.nodelay = uint32(nodelay)
		if nodelay != 0 {
			kcp.rx_minrto = IKCP_RTO_NDL
		} else {
			kcp.rx_minrto = IKCP_RTO_MIN
		}
	}
	if interval >= 0 {
		if interval > 5000 {
			interval = 5000
		} else if interval < 10 {
			interval = 10
		}
		kcp.interval = uint32(interval)
	}
	if resend >= 0 {
		kcp.fastresend = resend
	}
	if nc >= 0 {
		kcp.nocwnd = nc
	}
	return 0
}

func Ikcp_wndsize(kcp *Ikcpcb, sndwnd, rcvwnd int32) int32 {
	if kcp != nil {
		if sndwnd > 0 {
			kcp.snd_wnd = uint32(sndwnd)
		}
		if rcvwnd > 0 {
			kcp.rcv_wnd = uint32(rcvwnd)
		}
	}
	return 0
}

func Ikcp_waitsnd(kcp *Ikcpcb) int32 {
	return int32(kcp.nsnd_buf + kcp.nsnd_que)
}
