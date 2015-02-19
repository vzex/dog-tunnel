package pipe

import (
	"log"
	"strconv"
	"testing"
	"time"
)

func server() {
	l, err := Listen("127.0.0.1:4444")
	if err != nil {
		log.Println("listen port fail", err.Error())
		return
	}
	log.Println("listen", "ok")
	for {
		conn, err := l.Accept()
		log.Println(err, "connect")
		go func() {
			buff := make([]byte, 500)
			for {
				n, e := conn.Read(buff)
				if e != nil {
					break
				}
				log.Println("got", conn.RemoteAddr().String(), string(buff[:n]))
				conn.Write(buff[:n])
			}
			log.Println("server begin close connection")
			conn.Close()
			log.Println("server close connection")
		}()
	}
	log.Println("server quit")
}

func client() {
	conn, e := Dial("127.0.0.1:4444")
	if conn == nil {
		log.Println("byebyte", e.Error())
		return
	}
	log.Println("dial", "ok")
	t := time.Tick(time.Second)
	i := 0
	buff := make([]byte, 500)
	for {
		<-t
		i++
		conn.Write([]byte("hello world" + strconv.Itoa(i)))
		log.Println("loop", i)
		n, e := conn.Read(buff)
		log.Println("get", string(buff[:n]))
		if i == 4 {
			conn.Close()
		}
		if e != nil {
			break
		}
	}
	log.Println("client quit")
}
func TestNetwork(t *testing.T) {
	go server()
	go client()
	time.Sleep(10 * time.Second)
}
