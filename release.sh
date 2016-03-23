#!/bin/bash
version=$1
if [ $# -eq 0 ] 
then
        echo "Please input version, like \"./release.sh 0.60\""
        exit
fi
rm -f dtunnel_*$1.tgz
echo "Build ReleaseFile for version $version"

echo "build linux_amd64"
GOOS=linux GOARCH=amd64 make
tar zcvf dtunnel_linux_x64_$1.tgz dtunnel dtunnel_s
echo "build linux_386"
GOOS=linux GOARCH=386 make
tar zcvf dtunnel_linux_x86_$1.tgz dtunnel dtunnel_s
echo "build mac_x64"
GOOS=darwin GOARCH=amd64 make
tar zcvf dtunnel_mac_x64_$1.tgz dtunnel dtunnel_s
echo "build win32"
GOOS=windows GOARCH=386 make && mv dtunnel dtunnel.exe && mv dtunnel_s dtunnel_s.exe
tar zcvf dtunnel_win32_$1.tgz dtunnel.exe dtunnel_s.exe
echo "build linux_arm"
GOOS=linux GOARCH=arm make
tar zcvf dtunnel_linux_arm_$1.tgz dtunnel dtunnel_s
rm -f dtunnel dtunnel.exe dtunnel_s dtunnel_s.exe
echo "Build Over"
ls -l dtunnel_*$1.tgz
