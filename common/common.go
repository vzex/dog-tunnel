package common

import (
	"bufio"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
)

var encodingData []byte = []byte("bertdfvuifu4359c")
var encodingLen int = 16

func initxor() {
	encodingLen = len(encodingData)
}

func init() {
	initxor()
}

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

func XorSetKey(s string) {
	encodingData = []byte(s)
	initxor()
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

func WriteCrypt(conn net.Conn, id string, action string, content string, encode func([]byte) []byte) error {
	if encode != nil {
		return Write(conn, id, action, string(encode([]byte(content))))
	} else {
		return Write(conn, id, action, content)
	}
}

func Write(conn net.Conn, id string, action string, content string) error {
	if conn == nil {
		return nil
	}
	l1 := len(id)
	action = Xor(action)
	l2 := len(action)
	l3 := len(content)
	var buf []byte = make([]byte, l1+l2+l3+4*3)
	binary.LittleEndian.PutUint32(buf, uint32(l1))
	binary.LittleEndian.PutUint32(buf[4:], uint32(l2))
	binary.LittleEndian.PutUint32(buf[8:], uint32(l3))
	copy(buf[12:], []byte(id))
	copy(buf[12+l1:], []byte(action))
	copy(buf[12+l1+l2:], []byte(content))
	_, err := conn.Write(buf)
	//println("write!!!", old, l1, l2, l3)
	if err != nil {
		log.Println("write err", err.Error())
	}
	return err
}

type ReadCallBack func(conn net.Conn, id string, action string, arg string)

func ReadUDP(conn net.Conn, callback ReadCallBack, bufsize int) {
	//bufio.Scanner not work for large data, because the udppipe.Read(b []byte) func can't read a non-complete data to b
	buffer := make([]byte, bufsize)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			log.Println(err.Error())
			break
		}
		if n > 0 {
			split(buffer[:n], false, conn, callback)
		}
	}
}

func split(data []byte, atEOF bool, conn net.Conn, callback ReadCallBack) (adv int, token []byte, err error) {
	l := len(data)
	if l < 12 {
		return 0, nil, nil
	}
	if l > 1000000 {
		conn.Close()
		log.Println("invalid query!")
		return 0, nil, errors.New("to large data!")
	}
	var l1, l2, l3 uint32
	l1 = binary.LittleEndian.Uint32(data)
	l2 = binary.LittleEndian.Uint32(data[4:])
	l3 = binary.LittleEndian.Uint32(data[8:])
	tail := l - 12
	if tail < int(l1+l2+l3) {
		return 0, nil, nil
	}
	id := string(data[12 : 12+l1])
	action := string(data[12+l1 : 12+l1+l2])
	content := string(data[12+l1+l2 : 12+l1+l2+l3])
	callback(conn, string(id), Xor(string(action)), string(content))
	//println("read11!!", l1,l2, l3,string(id), Xor(string(action)), string(content))
	return 12 + int(l1+l2+l3), []byte{}, nil
}

func Read(conn net.Conn, callback ReadCallBack) {
	scanner := bufio.NewScanner(conn)
	scanner.Split(func(data []byte, atEOF bool) (adv int, token []byte, err error) {
		return split(data, atEOF, conn, callback)
	})
	for scanner.Scan() {
	}
	if scanner.Err() != nil {
		log.Println(scanner.Err().Error())
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
