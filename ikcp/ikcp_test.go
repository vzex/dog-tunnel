package ikcp
import "encoding/binary"
import "bytes"
import "time"
import "fmt"
import "testing"
//=====================================================================
//=====================================================================

// 模拟网络
var vnet *LatencySimulator 

// 模拟网络：模拟发送一个 udp包
func udp_output(buf []byte, _len int32, kcp *ikcpcb, user []byte) int32 {
        var id uint32 = uint32(user[0])
        //println("send!!!!", id, _len)
	if vnet.send(int(id), buf, int(_len)) != 1 {
                //println("wocao !!!", id, _len)
        }
	return 0
}

// 测试用例
func test(mode int) {
	// 创建模拟网络：丢包率10%，Rtt 60ms~125ms
	vnet = &LatencySimulator{}
        vnet.Init(10, 60, 125, 1000)

	// 创建两个端点的 kcp对象，第一个参数 conv是会话编号，同一个会话需要相同
	// 最后一个是 user参数，用来传递标识
        a := []byte {0}
        b := []byte {1}
        kcp1 := Ikcp_create(0x11223344, a)
        kcp2 := Ikcp_create(0x11223344, b)

	// 设置kcp的下层输出，这里为 udp_output，模拟udp网络输出函数
	kcp1.output = udp_output
	kcp2.output = udp_output

        current := uint32(iclock())
        slap := current + 20
        index := 0
        next := 0
	var sumrtt uint32 = 0
        count := 0
        maxrtt := 0

	// 配置窗口大小：平均延迟200ms，每20ms发送一个包，
	// 而考虑到丢包重发，设置最大收发窗口为128
	Ikcp_wndsize(kcp1, 128, 128)
	Ikcp_wndsize(kcp2, 128, 128)

	// 判断测试用例的模式
	if (mode == 0) {
		// 默认模式
		Ikcp_nodelay(kcp1, 0, 10, 0, 0)
		Ikcp_nodelay(kcp2, 0, 10, 0, 0)
	} else if (mode == 1) {
		// 普通模式，关闭流控等
		Ikcp_nodelay(kcp1, 0, 10, 0, 1)
		Ikcp_nodelay(kcp2, 0, 10, 0, 1)
	}	else {
		// 启动快速模式
		// 第二个参数 nodelay-启用以后若干常规加速将启动
		// 第三个参数 interval为内部处理时钟，默认设置为 10ms
		// 第四个参数 resend为快速重传指标，设置为2
		// 第五个参数 为是否禁用常规流控，这里禁止
		Ikcp_nodelay(kcp1, 1, 10, 2, 1)
		Ikcp_nodelay(kcp2, 1, 10, 2, 1)
	}


	var buffer []byte = make([]byte, 2000)
	var hr int32

        ts1 := iclock()

	for {
                time.Sleep(100* time.Millisecond)
		current = uint32(iclock())
		Ikcp_update(kcp1,uint32(iclock()))
		Ikcp_update(kcp2, uint32(iclock()))

		// 每隔 20ms，kcp1发送数据
		for ; current >= slap; slap += 20 {
                        buf := new(bytes.Buffer)
                        binary.Write(buf, binary.LittleEndian, uint32(index))
                        index++
                        binary.Write(buf, binary.LittleEndian, uint64(current))
			// 发送上层协议包
                        Ikcp_send(kcp1, buf.Bytes(), 8)
                        //println("now", iclock())
		}

		// 处理虚拟网络：检测是否有udp包从p1->p2
                for {
			hr = vnet.recv(1, buffer, 2000)
			if (hr < 0) { 
                                break 
                        }
			// 如果 p2收到udp，则作为下层协议输入到kcp2
                        Ikcp_input(kcp2, buffer, int(hr))
		}

		// 处理虚拟网络：检测是否有udp包从p2->p1
                for {
			hr = vnet.recv(0, buffer, 2000)
			if (hr < 0) { break }
			// 如果 p1收到udp，则作为下层协议输入到kcp1
                        Ikcp_input(kcp1, buffer, int(hr))
                        //println("@@@@", hr, r)
		}

		// kcp2接收到任何包都返回回去
                for {
			hr = Ikcp_recv(kcp2, buffer, 10)
			// 没有收到包就退出
			if (hr < 0) { break }
			// 如果收到包就回射
                        buf := bytes.NewReader(buffer)
                        var sn uint32
                        binary.Read(buf, binary.LittleEndian, &sn)
			Ikcp_send(kcp2, buffer, int(hr))
		}

		// kcp1收到kcp2的回射数据
                for {
			hr = Ikcp_recv(kcp1, buffer, 10)
                        buf := bytes.NewReader(buffer)
			// 没有收到包就退出
			if (hr < 0) { break }
                        var sn uint32
                        var ts, rtt uint32
                        binary.Read(buf, binary.LittleEndian, &sn)
                        binary.Read(buf, binary.LittleEndian, &ts)
			rtt = uint32(current) - ts
			
			if (sn != uint32(next)) {
				// 如果收到的包不连续
                                for i:=0;i<8 ;i++ {
                                        //println("---", i, buffer[i])
                                }
				println("ERROR sn ", count, "<->", next, sn)
                                return
			}

			next++
			sumrtt += rtt
			count++
			if (rtt > uint32(maxrtt)) { maxrtt = int(rtt) }

			println("[RECV] mode=", mode, " sn=",sn, " rtt=", rtt)
		}
		if (next > 1000) { break }
	}

	ts1 = iclock() - ts1

        names := []string{ "default", "normal", "fast" }
	fmt.Printf("%s mode result (%dms):\n", names[mode], ts1)
	fmt.Printf("avgrtt=%d maxrtt=%d\n", int(sumrtt / uint32(count)), maxrtt)
	fmt.Printf("press enter to next ...\n")
	var ch byte
        fmt.Scanf("%c", &ch)
}

func TestNetwork(t *testing.T) {
	test(0);	// 默认模式，类似 TCP：正常模式，无快速重传，常规流控
	test(1);	// 普通模式，关闭流控等
	test(2);	// 快速模式，所有开关都打开，且关闭流控
}

/*
default mode result (20917ms):
avgrtt=740 maxrtt=1507

normal mode result (20131ms):
avgrtt=156 maxrtt=571

fast mode result (20207ms):
avgrtt=138 maxrtt=392
*/

