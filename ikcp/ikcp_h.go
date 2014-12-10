package ikcp
import "container/list"
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
//---------------------------------------------------------------------
// IKCPCB
//---------------------------------------------------------------------
type IKCPCB struct {
	conv, mtu, mss, state uint32
		snd_una, snd_nxt, rcv_nxt uint32
		ts_recent, ts_lastack, ssthresh uint32
		rx_rttval, rx_srtt, rx_rto, rx_minrto uint32
		snd_wnd, rcv_wnd, rmt_wnd, cwnd, probe uint32
		current, interval, ts_flush, xmit uint32
		nrcv_buf, nsnd_buf uint32
		nrcv_que, nsnd_que uint32
		nodelay, updated uint32
		ts_probe, probe_wait uint32
		dead_link, incr uint32
		snd_queue, rcv_queue, snd_buf, rcv_buf *list.List
		acklist []uint32
		ackcount uint32
		ackblock uint32
		user interface{}
		buffer []byte
		fastresend int32
		nocwnd int32
		logmask int32
		writelog func (log []byte, kcp *Ikcpcb, user []byte)

		Output func (buf []byte, _len int32, kcp *Ikcpcb, user interface{}) (int32)
}


type Ikcpcb struct {IKCPCB}

const IKCP_LOG_OUTPUT =	1
const IKCP_LOG_INPUT = 2
const IKCP_LOG_SEND = 4
const IKCP_LOG_RECV = 8
const IKCP_LOG_IN_DATA = 16
const IKCP_LOG_IN_ACK = 32
const IKCP_LOG_IN_PROBE = 64
const IKCP_LOG_IN_WIN = 128
const IKCP_LOG_OUT_DATA =256
const IKCP_LOG_OUT_ACK = 512
const IKCP_LOG_OUT_PROBE = 1024
const IKCP_LOG_OUT_WINS = 2048
