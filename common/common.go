package common

import (
	"bufio"
	"net"
	"strconv"
)

const Version = 0.2

type ClientSetting struct {
	Name       string
	ClientType string
	Version    float32
	Delay      int
	Mode       int
}

func Write(conn net.Conn, id string, action string, content string) error {
	size := len(content)
	if conn == nil {
		return nil
	}
	str := id + ":" + action + ":" + strconv.Itoa(size) + ":" + content
	_, err := conn.Write([]byte(str))
	if err != nil {
		println("write err", err.Error())
	}
	return err
}

type ReadCallBack func(conn net.Conn, id string, action string, arg string)
type ReadUDPCallBack func(conn *net.UDPConn, addr *net.UDPAddr, id string, action string, arg string)

func Read(conn net.Conn, callback ReadCallBack) {
	scanner := bufio.NewScanner(conn)
	split := func(data []byte, atEOF bool) (adv int, token []byte, err error) {
		status := 0
		last := 0
		id := ""
		action := ""
		l := 0
		for i := 0; i < len(data); i++ {
			if data[i] == ':' {
				if status == 0 {
					id = string(data[0:i])
					status = 1
					last = i + 1
				} else if status == 1 {
					action = string(data[last:i])
					status = 2
					last = i + 1
				} else if status == 2 {
					l, _ = strconv.Atoi(string(data[last:i]))
					if len(data) >= i+1+l {
						content := data[i+1 : i+1+l]
						callback(conn, id, action, string(content))
						return i + 1 + l, content, nil
					} else {
						return 0, nil, nil
					}
				}
			} else if i > 15 && status == 0 {
				conn.Close()
				println("invalid query!")
				break
			}
		}
		return 0, nil, nil
	}
	scanner.Split(split)
	for scanner.Scan() {
	}
}

//udp
func ReadFromUDP(conn *net.UDPConn, addr *net.UDPAddr, data []byte, callback ReadUDPCallBack) bool {
	status := 0
	last := 0
	id := ""
	action := ""
	base := 0
	for i := 0; i < len(data); i++ {
		if data[i] == ':' {
			if status == 0 {
				id = string(data[base:i])
				status = 1
				last = i + 1
			} else if status == 1 {
				action = string(data[last:i])
				status = 2
				last = i + 1
			} else if status == 2 {
				l, _ := strconv.Atoi(string(data[last:i]))
				if len(data) >= i+1+l {
					content := data[i+1 : i+1+l]
					callback(conn, addr, id, action, string(content))
					return true
				} else {
					return false
				}
			}
		}
	}
	return false
}

type _reuseTbl struct {
	tbl map[string]bool
}

var currIdMap map[string]int
var reuseTbl map[string]*_reuseTbl

func GetId(name string) string {
	if reuseTbl != nil {
		tbl, bHave := reuseTbl[name]
		if bHave {
			if len(tbl.tbl) > 0 {
				for key := range tbl.tbl {
					delete(tbl.tbl, key)
					//					println("got old id", key)
					return key
				}
			}
		}
	}
	if currIdMap == nil {
		currIdMap = make(map[string]int)
		currIdMap[name] = 0
	}
	currIdMap[name]++
	//	println("gen new id", currIdMap[name])
	return strconv.Itoa(currIdMap[name])
}

func RmId(name, id string) {
	if currIdMap == nil {
		currIdMap = make(map[string]int)
		currIdMap[name] = 0
	}
	n, err := strconv.Atoi(id)
	if err != nil {
		return
	}
	if n > currIdMap[name] {
		return
	}
	if reuseTbl == nil {
		reuseTbl = make(map[string]*_reuseTbl)
	}
	tbl, bHave := reuseTbl[name]
	if !bHave {
		reuseTbl[name] = &_reuseTbl{tbl: make(map[string]bool)}
		tbl = reuseTbl[name]
	}
	tbl.tbl[id] = true
	//	println("can reuse ", name, id)
}

func Id_test(name string) {
	id1 := GetId(name)
	id2 := GetId(name)
	id3 := GetId(name)
	id4 := GetId(name)

	RmId(name, id2)
	RmId(name, id4)
	println(GetId(name))
	println(GetId(name))
	RmId(name, id1)
	println(GetId(name))
	RmId(name, id3)
	println(GetId(name))
	println(GetId(name))
}
