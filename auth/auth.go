package auth

import (
	"../common"
	"database/sql"
	"errors"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"log"
	"reflect"
	"time"
)

const (
	UserType_Normal = iota
	UserType_BlackList
	UserType_Super
	UserType_Admin

	CacheTime = 30

	DefaultMaxOnlineServerNum = 2
	DefaultMaxSessionNum      = 2
	DefaultMaxPipeNum         = 2
	DefaultMaxSameIPServers   = 2
	DefaultMaxCSModeData      = 10000000 //bytes
)

type User struct {
	//save to database
	UserName string
	Passwd   string
	UserType int
	AuthKey  string

	LastLoginTime      int64
	LastLogoutTime     int64
	MaxOnlineServerNum int
	MaxSessionNum      int
	MaxPipeNum         int
	MaxSameIPServers   int
	TodayCSModeData    int
	LimitDataSize      int `stop:"true"`
	//donnot save
	lastProcessTime int64
	//for cache
	overTime  int64
	cacheTime int64
}

func (u *User) CheckType() bool {
	if u.UserType == UserType_BlackList {
		return false
	}
	return true
}

func (u *User) OnLogin() {
	u.LastLoginTime = time.Now().Unix()
	u.lastProcessTime = u.LastLoginTime
	log.Println("OnLogin", u.lastProcessTime)
}

func (u *User) OnLogout() {
	u.LastLogoutTime = time.Now().Unix()
	updateUserDB(u)
}

func (u *User) CheckIpLimit(ip string) bool {
	if u.UserType == UserType_BlackList {
		return false
	}
	if u.UserType == UserType_Admin {
		return true
	}
	if common.GetOnlineServiceNumByNameAndIP(u.UserName, ip) >= u.MaxSameIPServers {
		return false
	}

	return true
}

func (u *User) CheckOnlineServiceNum() bool {
	if u.UserType == UserType_BlackList {
		return false
	}
	if u.UserType == UserType_Admin {
		return true
	}
	if common.GetOnlineServiceNumByName(u.UserName) >= u.MaxOnlineServerNum {
		return false
	}
	return true
}

func (u *User) CheckPipeNum(n int) bool {
	if u.UserType == UserType_BlackList {
		return false
	}
	if u.UserType == UserType_Admin {
		return true
	}
	if n > u.MaxPipeNum {
		return false
	}
	return true
}

func (u *User) CheckSessionNum(n int) bool {
	if u.UserType == UserType_BlackList {
		return false
	}
	if u.UserType == UserType_Admin {
		return true
	}
	if n >= u.MaxSessionNum {
		return false
	}
	return true
}

func (u *User) UpdateCSMode(size int) bool {
	if u.UserType == UserType_BlackList {
		return false
	}
	if u.UserType == UserType_Admin {
		return true
	}
	old := time.Unix(u.lastProcessTime, 0)
	now := time.Now()
	if now.Year() == old.Year() && now.YearDay() == old.YearDay() {
		u.TodayCSModeData += size
	} else {
		u.TodayCSModeData = size
	}
	u.lastProcessTime = now.Unix()
	n := DefaultMaxCSModeData
	if u.LimitDataSize > 0 {
		n = u.LimitDataSize
	}
	if u.TodayCSModeData > n {
		return false
	}
	return true
}

func (u *User) IsAlive() bool {
	return time.Now().Unix() < u.overTime
}

func (u *User) SetCacheTime(t int64) {
	if t >= 0 {
		u.cacheTime = t
	} else {
		t = u.cacheTime
	}
	u.overTime = t + time.Now().Unix()
}

func (u *User) DeInit() {
	updateUserDB(u)
	//log.Println("remove user from cache", u.UserName)
}

var g_Name2Users map[string]*User
var g_Database *sql.DB
var g_QueryUserStmt *sql.Stmt
var g_QueryUserNameByKeyStmt *sql.Stmt
var g_DelUserStmt *sql.Stmt
var g_AddUserStmt *sql.Stmt
var g_UpdateUserStmt *sql.Stmt

func Init(user, passwd, host string) error {
	g_Name2Users = make(map[string]*User)
	var err error
	g_Database, err = sql.Open("mysql", user+":"+passwd+"@tcp("+host+")/dogtunnel")
	if err != nil {
		return err
	}
	g_QueryUserStmt, err = g_Database.Prepare("SELECT UserName, Passwd, UserType, AuthKey, LastLoginTime, LastLogoutTime, MaxOnlineServerNum, MaxSessionNum, MaxPipeNum, MaxSameIPServers, TodayCSModeData, LimitDataSize FROM users WHERE UserName = ?")
	if err != nil {
		return err
	}
	g_QueryUserNameByKeyStmt, err = g_Database.Prepare("SELECT UserName FROM users WHERE AuthKey = ?")
	if err != nil {
		return err
	}
	g_DelUserStmt, err = g_Database.Prepare("DELETE FROM users where UserName = ?")
	if err != nil {
		return err
	}
	g_AddUserStmt, err = g_Database.Prepare("INSERT INTO users (UserName, Passwd, UserType, AuthKey, LastLoginTime, LastLogoutTime, MaxOnlineServerNum, MaxSessionNum, MaxPipeNum, MaxSameIPServers, TodayCSModeData, LimitDataSize) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
	if err != nil {
		return err
	}
	g_UpdateUserStmt, err = g_Database.Prepare("UPDATE users SET Passwd = ?, UserType = ?, AuthKey = ?, LastLoginTime = ? , LastLogoutTime = ?, MaxOnlineServerNum = ?, MaxSessionNum = ?, MaxPipeNum = ?, MaxSameIPServers = ?, TodayCSModeData = ?, LimitDataSize = ? WHERE UserName = ?")
	if err != nil {
		return err
	}
	go func() {
		c := time.Tick(time.Minute * 15)
		for _ = range c {
			g_Database.Ping()
		}
	}()
	return nil
}

func DeInit() {
	if g_Database != nil {
		g_Database.Close()
		g_Database = nil
	}
}

func preScan(struc interface{}) []interface{} {
	s := reflect.ValueOf(struc).Elem()
	s2 := reflect.TypeOf(struc).Elem()
	length := s.NumField()
	onerow := make([]interface{}, 0)
	for i := 0; i < length; i++ {
		onerow = append(onerow, s.Field(i).Addr().Interface())
		if s2.Field(i).Tag.Get("stop") != "" {
			break
		}
	}
	return onerow
}

var g_UserKey2Name map[string]string

func GetUserByKey(key string) (*User, error) {
	if g_UserKey2Name == nil {
		g_UserKey2Name = make(map[string]string)
	}
	var err error
	name, bHave := g_UserKey2Name[key]
	if !bHave {
		err = g_QueryUserNameByKeyStmt.QueryRow(key).Scan(&name)
		//fmt.Printf("load from db %+v\n", _user)
		if err == nil {
			g_UserKey2Name[key] = name
		}
		if err == sql.ErrNoRows {
			g_UserKey2Name[key] = ""
			err = nil
		}
	}
	if name != "" {
		return GetUser(name)
	}
	return nil, err
}

func GetUser(name string) (*User, error) {
	cache := common.GetCacheContainer("user")
	var user *User = nil
	var err error
	info := cache.GetCache(name)
	if info == nil {
		_user := &User{}
		row := preScan(_user)
		err = g_QueryUserStmt.QueryRow(name).Scan(row...)
		//fmt.Printf("load from db %+v,%d,%v\n", _user, _user.TodayCSModeData, err)
		if err == nil {
			user = _user
			cache.AddCache(name, _user, CacheTime)
			user.OnLogin()
		}
		if err == sql.ErrNoRows {
			err = nil
		}
	} else {
		user = info.(*User)
		user.SetCacheTime(-1)
	}
	return user, err
}

func DelUser(name string) (bool, error) {
	user, err := GetUser(name)
	if user != nil {
		if g_UserKey2Name != nil {
			delete(g_UserKey2Name, user.AuthKey)
		}
	}
	cache := common.GetCacheContainer("user")
	cache.DelCache(name)
	result, err := g_DelUserStmt.Exec(name)
	n, _ := result.RowsAffected()
	return n > 0, err
}

func updateUserDB(user *User) error {
	row := preScan(user)
	_row := append(row[1:], row[0])
	_, _err := g_UpdateUserStmt.Exec(_row...)
	if _err != nil {
		return _err
	}
	return nil
}

func UpdateUser(name string, user *User) error {
	cache := common.GetCacheContainer("user")
	info := cache.GetCache(name)
	if info != nil {
		cache.UpdateCache(name, user)
		return nil
	} else {
		return updateUserDB(user)
	}
}

var authBaseId int = 1
var staticKey string = "admin vzex"

func genUserKey(name string) string {
	authBaseId++
	return common.Md5(fmt.Sprintf("%d%.0f%s%s", authBaseId, time.Now().Unix(), name, staticKey))
}

func UpdateUserKey(name, key string) error {
	if g_UserKey2Name == nil {
		g_UserKey2Name = make(map[string]string)
	}
	user, err := GetUser(name)
	if err != nil {
		return err
	}

	if user != nil {
		if user.AuthKey == key {
			return nil
		}
		g_UserKey2Name[user.AuthKey] = ""
	} else {
		return errors.New("no user")
	}
	g_UserKey2Name[key] = name
	user.AuthKey = key
	err = UpdateUser(name, user)
	return err
}

func GenUserKey(name string) string {
	if g_UserKey2Name == nil {
		g_UserKey2Name = make(map[string]string)
	}
	for i := 0; i < 10; i++ {
		key := genUserKey(name)
		_, bHave := g_UserKey2Name[key]
		if !bHave {
			return key
		}
	}
	return ""
}

func AddUser(name string, user *User) (string, error) {
	old, err := GetUser(name)
	if old != nil {
		return "", errors.New("already have user")
	}
	if err != nil {
		return "", err
	}
	key := GenUserKey(name)
	if key == "" {
		return "", errors.New("gen user key fail")
	}
	user.AuthKey = key
	row := preScan(user)
	_, _err := g_AddUserStmt.Exec(row...)
	if _err != nil {
		return "", _err
	}
	if g_UserKey2Name == nil {
		g_UserKey2Name = make(map[string]string)
	}
	g_UserKey2Name[user.AuthKey] = name
	return user.AuthKey, nil
}

func GetUserNameList(limita, limitb string) []string {
	names := []string{}
	rows, err := g_Database.Query("select UserName from users limit " + limita + "," + limitb)
	if err != nil {
		return names
	}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err == nil {
			names = append(names, name)
		}
	}
	return names
}

/*
func main() {
	err := Init("dog", "dog")
	if err != nil {
		panic(err)
	}
	defer DeInit()
	user, _err := GetUser("vzex")
	user, _err = GetUser("vzex")
	user, _err = GetUser("vzex")
	if _err == nil {
		fmt.Printf("%+v\n", *user)
	} else {
		panic(_err)
	}
	time.Sleep(time.Second * 31)
	user, _err = GetUser("vzex")
	time.Sleep(time.Second * 50)
}
*/
