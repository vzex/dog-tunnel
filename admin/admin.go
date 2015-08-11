package admin

import (
	"../auth"
	"../common"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
)

var g_AdminCommands map[string]cmdHandler

type cmdHandler func(w http.ResponseWriter, r *http.Request) (result string, bSuccess bool)

func addAdminCmd(cmd string, callback cmdHandler) {
	g_AdminCommands[cmd] = callback
}

func initAdminCmds() {
	g_AdminCommands = make(map[string]cmdHandler)
	addAdminCmd("servers", _adminGetServers)
	addAdminCmd("sessions", _adminGetSession)
	addAdminCmd("kicksession", _adminKickSession)
	addAdminCmd("kickserver", _adminKickServer)

	addAdminCmd("broadcast", _adminBroadcast)
	addAdminCmd("setglobal", _adminSetGlobal)
	addAdminCmd("getglobal", _adminGetGlobal)

	addAdminCmd("usersetting", _adminUserSetting)
}

func InitAdminPort(addr, certFile, keyFile string) error {
	initAdminCmds()
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", adminHandler)
	server := &http.Server{Addr: addr, Handler: mux}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if certFile != "" && keyFile != "" {
		config := &tls.Config{}
		config.NextProtos = []string{"http/1.1"}
		var err error
		config.Certificates = make([]tls.Certificate, 1)
		config.Certificates[0], err = tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return err
		}
		tlsListener := tls.NewListener(listener, config)
		go server.Serve(tlsListener)
	} else {
		go server.Serve(listener)
	}
	return nil
}

type handlerResult struct {
	Code int
	Msg  string
}

func adminHandler(w http.ResponseWriter, r *http.Request) {
	command := r.FormValue("cmd")
	if command != "" {
		handler, bHave := g_AdminCommands[command]
		if bHave {
			result, bOk := handler(w, r)
			if bOk {
				res, _ := json.Marshal(handlerResult{Code: 200, Msg: result})
				w.Write([]byte(res))
			} else {
				res, _ := json.Marshal(handlerResult{Code: 201, Msg: result})
				w.Write([]byte(res))
			}
			return
		}
	}
	res, _ := json.Marshal(handlerResult{Code: 202, Msg: "invalid command"})
	w.Write([]byte(res))
}

func _adminKickServer(w http.ResponseWriter, r *http.Request) (result string, bSuccess bool) {
	server := r.FormValue("server")
	if server == "" {
		result = "please spec server"
		bSuccess = false
		return
	}
	conn, bHave := common.ServerName2Conn[server]
	if bHave {
		common.Write(conn, "0", "showandquit", "admin kick you out")
		result = "kick server ok"
	} else {
		bSuccess = false
		result = "donnot have this serverName"
		return
	}
	bSuccess = true
	return
}

func _adminGetServers(w http.ResponseWriter, r *http.Request) (result string, bSuccess bool) {
	arr := make(map[string]([]string))
	for _, server := range common.Conn2ClientInfo {
		if server.IsServer {
			_arr, bHave := arr[server.UserName]
			if bHave {
				arr[server.UserName] = append(_arr, server.ServerName)
				arr[server.UserName] = append(arr[server.UserName], server.Conn.RemoteAddr().String())
			} else {
				arr[server.UserName] = []string{server.ServerName, server.Conn.RemoteAddr().String()}
			}
		}
	}
	_result, _ := json.Marshal(arr)
	result = string(_result)
	bSuccess = true
	return
}

func _adminKickSession(w http.ResponseWriter, r *http.Request) (result string, bSuccess bool) {
	server := r.FormValue("server")
	session := r.FormValue("session")
	if server == "" || session == "" {
		result = "please spec server and session"
		bSuccess = false
		return
	}
	conn, bHave := common.ServerName2Conn[server]
	if bHave {
		server, bHave2 := common.Conn2ClientInfo[conn]
		if bHave2 {
			session, bHave := server.Id2Session[session]
			if bHave {
				if session.ClientA != conn {
					common.Write(session.ClientA, "0", "showandquit", "admin kick you out")
				} else if session.ClientB != conn {
					common.Write(session.ClientB, "0", "showandquit", "admin kick you out")
				}
				result = "kick session ok"
			} else {
				result = "no need kick"
			}
		} else {
			bSuccess = false
			result = "donnot have this conn"
		}
	} else {
		bSuccess = false
		result = "donnot have this serverName"
		return
	}
	bSuccess = true
	return
}

func _adminGetSession(w http.ResponseWriter, r *http.Request) (result string, bSuccess bool) {
	server := r.FormValue("server")
	if server == "" {
		result = "please spec server"
		bSuccess = false
		return
	}
	arr := []string{}
	conn, bHave := common.ServerName2Conn[server]
	if bHave {
		server, bHave2 := common.Conn2ClientInfo[conn]
		if bHave2 {
			for _, session := range server.Id2Session {
				arr = append(arr, session.String())
			}
		} else {
			bSuccess = false
			result = "donnot have this conn"
		}
	} else {
		bSuccess = false
		result = "donnot have this serverName"
		return
	}
	_result, _ := json.Marshal(arr)
	result = string(_result)
	bSuccess = true
	return
}

func _adminBroadcast(w http.ResponseWriter, r *http.Request) (result string, bSuccess bool) {
	msgtype := r.FormValue("type")
	if msgtype == "" {
		result = "please spec type"
		bSuccess = false
		return
	}
	msg := r.FormValue("msg")
	quit := r.FormValue("quit")
	cmd := "show"
	if quit != "" {
		cmd = "showandquit"
	}
	n := 0
	for conn, info := range common.Conn2ClientInfo {
		hit := false
		if msgtype == "s" && info.IsServer {
			hit = true
		} else if msgtype == "c" && !info.IsServer {
			hit = true
		} else if msgtype == "a" {
			hit = true
		}
		if hit {
			common.Write(conn, "0", cmd, msg)
			n++
		}
	}
	result = fmt.Sprintf("%d", n)
	bSuccess = true
	return
}

func _adminSetGlobal(w http.ResponseWriter, r *http.Request) (result string, bSuccess bool) {
	key := r.FormValue("key")
	//value := r.FormValue("value")
	if key == "" {
		result = "please spec key"
		bSuccess = false
		return
	}
	result = ""
	bSuccess = true
	return
}

func _adminGetGlobal(w http.ResponseWriter, r *http.Request) (result string, bSuccess bool) {
	key := r.FormValue("key")
	if key == "" {
		result = "please spec key"
		bSuccess = false
		return
	}
	result = ""
	bSuccess = true
	return
}

func _adminUserSetting(w http.ResponseWriter, r *http.Request) (result string, bSuccess bool) {
	action := r.FormValue("action")
	key := r.FormValue("user")
	if key == "" && action != "list" {
		result = "please spec user"
		bSuccess = false
		return
	}
	switch action {
	case "limit":
		n := r.FormValue("size")
		size, _ := strconv.Atoi(n)

		user, err := auth.GetUser(key)
		if err != nil {
			result = err.Error()
			bSuccess = false
			return
		} else {
			user.LimitDataSize = size
			err := auth.UpdateUser(key, user)
			if err == nil {
				bSuccess = true
			} else {
				result = err.Error()
				bSuccess = false
			}
			return
		}
	case "add":
		passwd := r.FormValue("passwd")
		if passwd == "" {
			result = "please spec passwd"
			bSuccess = false
			return
		}
		_usertype := auth.UserType_Normal
		usertype := r.FormValue("type")
		maxOnlineServerNum := auth.DefaultMaxOnlineServerNum
		maxSessionNum := auth.DefaultMaxSessionNum
		maxPipeNum := auth.DefaultMaxPipeNum
		maxSameIPServers := auth.DefaultMaxSameIPServers
		switch usertype {
		case "black":
			_usertype = auth.UserType_BlackList
		case "super":
			_usertype = auth.UserType_Super
			maxOnlineServerNum = 10
			maxSessionNum = 10
			maxPipeNum = 10
			maxSameIPServers = 10
		case "admin":
			_usertype = auth.UserType_Admin
		}

		user := &auth.User{UserName: key, Passwd: common.HashPasswd(common.Md5(passwd)), UserType: _usertype, LastLoginTime: 0, LastLogoutTime: 0, MaxOnlineServerNum: maxOnlineServerNum, MaxSessionNum: maxSessionNum, MaxPipeNum: maxPipeNum, MaxSameIPServers: maxSameIPServers, TodayCSModeData: 0, LimitDataSize: 0}
		key, err := auth.AddUser(key, user)
		if err != nil {
			result = err.Error()
			bSuccess = false
			return
		} else {
			result = key
			bSuccess = true
			return
		}
	case "list":
		limita := r.FormValue("limita")
		limitb := r.FormValue("limitb")
		if limita == "" || limitb == "" {
			result = "please limita and limitb"
			bSuccess = false
			return
		}
		arr := auth.GetUserNameList(limita, limitb)
		res, _ := json.Marshal(arr)
		result = string(res)
		bSuccess = true
		return
	case "get":
		user, err := auth.GetUser(key)
		if err != nil {
			result = err.Error()
			bSuccess = false
			return
		} else {
			if user == nil {
				result = "donnot have this user"
				bSuccess = false
				return
			}

			res, _ := json.Marshal(user)
			result = string(res)
			bSuccess = true
			return
		}
	case "del":
		bHave, err := auth.DelUser(key)
		if err != nil {
			result = err.Error()
			bSuccess = false
			return
		} else {
			if !bHave {
				result = "donnot have this user"
			}
			bSuccess = true
			return
		}
	case "key":
		_key := auth.GenUserKey(key)
		if _key == "" {
			result = "gen user key fail"
			bSuccess = false
			return
		}
		err := auth.UpdateUserKey(key, _key)
		if err == nil {
			result = _key
			bSuccess = true
		} else {
			result = err.Error()
			bSuccess = false
		}
		return
	case "set":
		_usertype := -1
		maxOnlineServerNum := -1
		maxSessionNum := -1
		maxPipeNum := -1
		maxSameIPServers := -1
		pass := ""
		passwd := r.FormValue("passwd")
		if passwd != "" {
			pass = common.HashPasswd(common.Md5(passwd))
		}
		usertype := r.FormValue("type")
		if usertype != "" {
			switch usertype {
			case "black":
				_usertype = auth.UserType_BlackList
			case "super":
				_usertype = auth.UserType_Super
				maxOnlineServerNum = 10
				maxSessionNum = 10
				maxPipeNum = 10
			case "normal":
				_usertype = auth.UserType_Normal
				maxOnlineServerNum = auth.DefaultMaxOnlineServerNum
				maxSessionNum = auth.DefaultMaxSessionNum
				maxPipeNum = auth.DefaultMaxPipeNum
				maxSameIPServers = auth.DefaultMaxSameIPServers
			case "admin":
				_usertype = auth.UserType_Admin
			}
		}
		servern := r.FormValue("serven")
		if servern != "" {
			maxOnlineServerNum, _ = strconv.Atoi(servern)
		}
		sessionn := r.FormValue("sessionn")
		if sessionn != "" {
			maxSessionNum, _ = strconv.Atoi(sessionn)
		}
		pipen := r.FormValue("pipen")
		if pipen != "" {
			maxPipeNum, _ = strconv.Atoi(pipen)
		}
		ipn := r.FormValue("sameip")
		if ipn != "" {
			maxSameIPServers, _ = strconv.Atoi(ipn)
		}
		user, err := auth.GetUser(key)
		if err != nil {
			result = err.Error()
			bSuccess = false
			return
		} else {
			if _usertype != -1 {
				user.UserType = _usertype
			}
			if maxOnlineServerNum != -1 {
				user.MaxOnlineServerNum = maxOnlineServerNum
			}
			if maxSessionNum != -1 {
				user.MaxSessionNum = maxSessionNum
			}
			if maxPipeNum != -1 {
				user.MaxPipeNum = maxPipeNum
			}
			if maxSameIPServers != -1 {
				user.MaxSameIPServers = maxSameIPServers
			}
			if pass != "" {
				user.Passwd = pass
			}
			err := auth.UpdateUser(key, user)
			if err == nil {
				bSuccess = true
			} else {
				result = err.Error()
				bSuccess = false
			}
			return
		}
	default:
		result = "invalid action"
		bSuccess = false
		return
	}
	result = ""
	bSuccess = true
	return
}
