#!/bin/bash
# first run server,make client,and reg a,then run this bash to test
declare -i i=0
declare -i maxN=30

while [ $i -lt $maxN ]
do
	declare -i j=$i+10000
	./dtunnel -link a -local :$j -pipen 4 -v > test_$j.log 2>&1 &
	i=$i+1
done
#maybe longer
sleep 5
declare -i n=`grep "service start success" test*.log|wc -l`
if [ $n -eq $maxN ] 
then
	echo "test ok"
else
	cat test*.log
fi
ps aux|grep "link a"|grep -v grep|awk '{print $2}'|xargs kill
rm test*.log
