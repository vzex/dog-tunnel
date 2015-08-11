use dogtunnel;

DROP TABLE IF EXISTS users;
CREATE TABLE users(
	UserName varchar(50) NOT NULL,
	Passwd varchar(50) NOT	NULL,
	UserType tinyint  NOT NULL DEFAULT 0,
	AuthKey varchar(40) NOT NULL DEFAULT "",
	LastLoginTime int(11) NOT NULL DEFAULT 0,
	LastLogoutTime int(11) NOT NULL DEFAULT 0,
	MaxOnlineServerNum int NOT NULL DEFAULT 2,
	MaxSessionNum int NOT NULL DEFAULT 2,
	MaxPipeNum int NOT NULL DEFAULT 2,
	MaxSameIPServers int NOT NULL DEFAULT 2,
	TodayCSModeData int NOT NULL DEFAULT 0,
	LimitDataSize int NOT NULL DEFAULT 0,
	PRIMARY KEY (UserName),
	UNIQUE KEY (AuthKey)
) ENGINE=InnoDB DEFAULT CHARSET=latin1;
