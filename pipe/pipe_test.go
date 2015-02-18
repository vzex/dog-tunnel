package pipe
import ("testing"
	"time"
	"strconv")

func server() {
	l,err:=Listen("127.0.0.1:4444")
	if err != nil {
		println("listen port fail", err.Error())
		return
	}
	println(l, "ok")
	for {
		conn, err := l.Accept()
		println(conn, err, "connect")
		go func() {
			buff := make([]byte, 500)
			for {
				n,e:=conn.Read(buff)
				if e!=nil {
					break
				}
				println("got", conn.RemoteAddr().String(), string(buff[:n]))
				conn.Write(buff[:n])
			}
			conn.Close()
			println("close connection")
		}()
	}
}

func client() {
	conn,e:=Dial("127.0.0.1:4444")
	if conn == nil {
		println("byebyte", e.Error())
		return
	}
	println(conn, "ok")
	t:=time.Tick(time.Second)
	i:=0
	buff:=make([]byte, 500)
	for {
		<-t
		i++
		conn.Write([]byte("hello world"+strconv.Itoa(i)))
		println("loop", i)
		n, e:=conn.Read(buff)
		println("get", string(buff[:n]))
		if e != nil {
			break
		}
	}
}
func TestNetwork(t *testing.T) {
	go server()
	go client()
	time.Sleep(10*time.Second)
}

