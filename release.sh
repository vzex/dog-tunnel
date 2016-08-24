#!/bin/bash
version=$1
if [ $# -eq 0 ] 
then
	echo "Please input version, like \"./release.sh 0.60\""
	exit
fi
rm -f dtunnel_*$1_lite.tgz
echo "Build ReleaseFile for version $version"

#cd $GOROOT/src
#GOOS=darwin GOARCH=amd64 sh ./make.bash
#cd -
echo "build linux_amd64"
GOOS=linux GOARCH=amd64 make
tar zcvf dtunnel_linux_x64_$1_lite.tgz dtunnel_lite
echo "build linux_386"
GOOS=linux GOARCH=386 make
tar zcvf dtunnel_linux_x86_$1_lite.tgz dtunnel_lite
echo "build mac_x64"
GOOS=darwin GOARCH=amd64 make
tar zcvf dtunnel_mac_x64_$1_lite.tgz dtunnel_lite
echo "build win32"
GOOS=windows GOARCH=386 make && mv dtunnel_lite dtunnel_lite.exe
tar zcvf dtunnel_win32_$1_lite.tgz dtunnel_lite.exe
echo "build win64"
GOOS=windows GOARCH=amd64 make && mv dtunnel_lite dtunnel_lite.exe
tar zcvf dtunnel_win64_$1_lite.tgz dtunnel_lite.exe
#cd $GOROOT/src
#GOOS=linux GOARCH=arm sh ./make.bash
#cd -
echo "build linux_arm"
GOOS=linux GOARCH=arm make
tar zcvf dtunnel_linux_arm_$1_lite.tgz dtunnel_lite
rm -f dtunnel_lite dtunnel_lite.exe
echo "Build Over"
ls -l dtunnel_*$1_lite.tgz
