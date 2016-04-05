package common

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
)

const Version = 0.70

type ClientSetting struct {
	AccessKey string
	ClientKey string

	Name       string
	ClientType string
	Version    float32
	Delay      int
	Mode       int
	PipeNum    int
	AesKey     string
}

var encodingData []byte = []byte("bertdfvuifu4359c")
var encodingLen int = 16
var headerLen int = 4

func init() {
	encodingLen = len(encodingData)
	headerLen = binary.Size(uint32(1))
}

func Xor(s string) string {
	n := len(s)
	if n == 0 {
		return ""
	}
	r := make([]byte, n)
	for i := 0; i < n; i++ {
		r[i] = s[i] ^ encodingData[i%encodingLen]
	}
	return string(r)
}

func Write(conn net.Conn, id string, action string, content string) error {
	if conn == nil {
		return nil
	}
	l1 := len(id)
	action = Xor(action)
	l2 := len(action)
	l3 := len(content)
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint32(l1))
	binary.Write(&buf, binary.LittleEndian, uint32(l2))
	binary.Write(&buf, binary.LittleEndian, uint32(l3))
	binary.Write(&buf, binary.LittleEndian, []byte(id))
	binary.Write(&buf, binary.LittleEndian, []byte(action))
	binary.Write(&buf, binary.LittleEndian, []byte(content))
	_, err := conn.Write(buf.Bytes())
	//println("write!!!", old, l1, l2, l3)
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
		l := len(data)
		if l < headerLen*3 {
			return 0, nil, nil
		}
		if l > 1048576 {  //1024*1024=1048576
			conn.Close()
			log.Println("invalid query!")
			return 0, nil, errors.New("too large data!")
		}
		var l1, l2, l3 uint32
		buf := bytes.NewReader(data)
		binary.Read(buf, binary.LittleEndian, &l1)
		binary.Read(buf, binary.LittleEndian, &l2)
		binary.Read(buf, binary.LittleEndian, &l3)
		tail := l - headerLen*3
		lhead := l1 + l2 + l3
		if lhead > 1048576 {
			conn.Close()
			log.Println("invalid query2!")
			return 0, nil, errors.New("too large data!")
		}
		if uint32(tail) < lhead {
			return 0, nil, nil
		}
		id := make([]byte, l1)
		action := make([]byte, l2)
		content := make([]byte, l3)
		binary.Read(buf, binary.LittleEndian, &id)
		binary.Read(buf, binary.LittleEndian, &action)
		binary.Read(buf, binary.LittleEndian, &content)
		callback(conn, string(id), Xor(string(action)), string(content))
		//println("read11!!", l1,l2, l3,string(id), Xor(string(action)), string(content))
		return headerLen*3 + int(l1+l2+l3), []byte{}, nil
	}
	scanner.Split(split)
	for scanner.Scan() {
	}
	if scanner.Err() != nil {
		println(scanner.Err().Error())
	}
}

func Md5(msg string) string {
	h := md5.New()
	io.WriteString(h, msg)
	return fmt.Sprintf("%x", h.Sum(nil))
}

func HashPasswd(pass string) string {
	return Md5(pass + "testzc222sf")
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
	return
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
