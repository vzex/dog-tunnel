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
)

var encodingData []byte = []byte("bertdfvuifu4359c")
var encodingLen int = 16

func initxor() {
	encodingLen = len(encodingData)
}

func init() {
	initxor()
}

const Version = 1.31

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

func WriteCrypt(conn net.Conn, id int, action byte, content []byte, encode func([]byte) []byte) error {
	if encode != nil {
		return Write(conn, id, action, encode(content))
	} else {
		return Write(conn, id, action, content)
	}
}

func Write(conn net.Conn, id int, action byte, content []byte) error {
	if conn == nil {
		return nil
	}
	l := len(content)
	var buf []byte
	var size int
	if l > 0 {
		size = 10 + l
		buf = make([]byte, size) //4+1+1+4 id action isShort? len(content) content
	} else {
		size = 6
		buf = make([]byte, size) //4+1+1 id action isShort?
	}
	buf[0] = byte(id)
	buf[1] = byte(id >> 8)
	buf[2] = byte(id >> 16)
	buf[3] = byte(id >> 24)
	buf[4] = action
	if l > 0 {
		buf[5] = 0
		binary.LittleEndian.PutUint32(buf[6:], uint32(l))
		copy(buf[10:], []byte(content))
	} else {
		buf[5] = 1
	}
	_, err := conn.Write(buf[:size])
	//println("write!!!", old, l1, l2, l3)
	if err != nil {
		log.Println("write err", err.Error())
	}
	return err
}

type ReadCallBack func(conn net.Conn, id int, action byte, arg []byte)

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
	if l < 6 {
		return 0, nil, nil
	}
	if l > 100000 {
		conn.Close()
		log.Println("invalid query!")
		return 0, nil, errors.New("to large data!")
	}
	var id int
	var action byte
	id = int(int32(data[0]) | int32(data[1])<<8 | int32(data[2])<<16 | int32(data[3])<<24)
	action = data[4]
	isShort := data[5]
	var content []byte
	var offset int
	if isShort == 1 {
		offset = 6
	} else {
		if l < 10 {
			return 0, nil, nil
		}
		ls := binary.LittleEndian.Uint32(data[6:])
		tail := l - 10
		if tail < int(ls) {
			return 0, nil, nil
		}
		content = data[10 : 10+ls]
		offset = 10 + int(ls)
	}
	callback(conn, id, action, content)
	//println("read11!!", l1,l2, l3,string(id), Xor(string(action)), string(content))
	return offset, []byte{}, nil
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
	tbl map[int]bool
}

var currIdMap map[string]int
var reuseTbl map[string]*_reuseTbl

func GetId(name string) int {
	if currIdMap == nil {
		currIdMap = make(map[string]int)
		currIdMap[name] = 0
	}
	i, _ := currIdMap[name]
	i++
	if i >= 2147483647 {
		i = 0
	}
	currIdMap[name] = i
	//	println("gen new id", currIdMap[name])
	return i
}

func RmId(name string, id int) {
	return
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
