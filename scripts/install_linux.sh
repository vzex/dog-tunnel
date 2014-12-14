#!/bin/sh
# need run as root
cd ~
wget https://storage.googleapis.com/golang/go1.4.linux-amd64.tar.gz
tar zxvf go1.4.linux-amd64.tar.gz
echo 'export GOROOT=/root/go' >> .bashrc
echo 'export GOPATH=/root/go/bin' >> .bashrc
echo 'export PATH="/root/go/bin":$PATH' >> .bashrc
source .bashrc
yum install -y git
git clone https://github.com/vzex/dog-tunnel.git
cd dog-tunnel
go get github.com/go-sql-driver/mysql
make
mv dtunnel /usr/bin/dtunnel

