//+build !windows
//+build !darwin

package platform

import "fmt"
import "syscall"
import "net"
import "log"

func GetDestAddrFromConn(conn net.Conn) string {
	f, er := conn.(*net.TCPConn).File()
	defer f.Close()
	if er == nil {
		fd := f.Fd()
		syscall.SetNonblock(int(fd), true)
		addr, _er := syscall.GetsockoptIPv6Mreq(int(fd), syscall.SOL_IP, 80)
		if _er == nil {
			remote := fmt.Sprintf("%d.%d.%d.%d:%d", uint(addr.Multiaddr[4]), uint(addr.Multiaddr[5]), uint(addr.Multiaddr[6]), uint(addr.Multiaddr[7]), uint16(addr.Multiaddr[2])<<8+uint16(addr.Multiaddr[3]))
			log.Println("redirect ip", remote)
			return remote
		} else {
			log.Println("get ip fail:", _er.Error())
		}
	} else {
		log.Println(er.Error())
	}
	return ""

}
