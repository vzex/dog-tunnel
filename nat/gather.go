package nat

import (
	"./stun"
	"bytes"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"net"
	"strings"
)

var stunserver = flag.String("stun", "",
	"STUN server to query for reflexive address,ex:stun.l.google.com:19302")

var lanNets = []*net.IPNet{
	{net.IPv4(10, 0, 0, 0), net.CIDRMask(8, 32)},
	{net.IPv4(172, 16, 0, 0), net.CIDRMask(12, 32)},
	{net.IPv4(192, 168, 0, 0), net.CIDRMask(16, 32)},
	{net.ParseIP("fc00"), net.CIDRMask(7, 128)},
}

type candidate struct {
	Addr *net.UDPAddr
}

func (c candidate) String() string {
	return fmt.Sprintf("%v", c.Addr)
}

func (c candidate) Equal(c2 candidate) bool {
	return c.Addr.IP.Equal(c2.Addr.IP) && c.Addr.Port == c2.Addr.Port
}

func getReflexive(sock *net.UDPConn) (string, int, error) {
	serverAddr, err := net.ResolveUDPAddr("udp", *stunserver)
	if err != nil {

		return "", 0, errors.New("Couldn't resolve STUN server")
	}
	//println("connect stun server", *stunserver)

	var tid [12]byte
	if _, err = rand.Read(tid[:]); err != nil {
		return "", 0, err
	}

	request, err := stun.BindRequest(tid[:], nil, nil, true, false)
	if err != nil {
		return "", 0, err
	}

	n, err := sock.WriteTo(request, serverAddr)
	if err != nil {
		return "", 0, err
	}
	if n < len(request) {
		return "", 0, err
	}

	var buf [1024]byte
	n, _, err = sock.ReadFromUDP(buf[:])
	if err != nil {
		return "", 0, err
	}

	packet, err := stun.ParsePacket(buf[:n], nil)
	if err != nil {
		return "", 0, err
	}

	if packet.Class != stun.ClassSuccess || packet.Method != stun.MethodBinding || packet.Addr == nil || !bytes.Equal(tid[:], packet.Tid[:]) {
		return "", 0, errors.New("No address provided by STUN server")
	}

	return packet.Addr.IP.String(), packet.Addr.Port, nil
}

func pruneDups(cs []candidate) []candidate {
	ret := make([]candidate, 0, len(cs))
	for _, c := range cs {
		unique := true
		for _, c2 := range ret {
			if c.Equal(c2) {
				unique = false
				break
			}
		}
		if unique {
			ret = append(ret, c)
		}
	}
	return ret
}

func GatherCandidates(sock *net.UDPConn, outIpList string) ([]candidate, error) {
	laddr := sock.LocalAddr().(*net.UDPAddr)
	ret := []candidate{}
	switch {
	case laddr.IP.IsLoopback():
		return nil, errors.New("Connecting over loopback not supported")
	case laddr.IP.IsUnspecified():
		addrs, err := net.InterfaceAddrs()
		if err != nil {
			return nil, err
		}

		for _, addr := range addrs {
			ip, ok := addr.(*net.IPNet)
			if ok && ip.IP.IsGlobalUnicast() {
				ret = append(ret, candidate{&net.UDPAddr{IP: ip.IP, Port: laddr.Port}})
			}
		}
	default:
		ret = append(ret, candidate{laddr})
	}

	addip := func(ipStr string, port int) {
		ip := net.ParseIP(ipStr)
		if port == 0 {
			port = laddr.Port
		}
		bHave := false
		for _, info := range ret {
			if info.Addr.IP.Equal(ip) && info.Addr.Port == port {
				bHave = true
				break
			}
		}
		if !bHave {
			ret = append(ret, candidate{&net.UDPAddr{IP: ip, Port: port}})
		}
	}
	// Get the reflexive address
	if *stunserver != "" {
		ip, port, err := getReflexive(sock)
		if err == nil {
			addip(ip, port)
		}
	}

	arr := strings.Split(outIpList, ";")
	for _, ip := range arr {
		addip(ip, 0)
	}

	/*	for _, info := range ret {
			log.Println("init ip:", info.Addr.String())
	}*/
	return ret, nil
}
