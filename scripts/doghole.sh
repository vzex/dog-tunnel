#!/bin/sh
# move dtunnel to $HOME/bin/dtunnel
# echo "mypassword" > $HOME/.ssh/pw

cat $HOME/.ssh/pw | sudo -S killall -9 dtunnel
sleep 2


# the server side

cat $HOME/.ssh/pw | sudo -S nice -n -10 $HOME/bin/dtunnel --reg node1.domain.com -local socks5 -clientkey verylongpasswd &

# the client side

cat $HOME/.ssh/pw | sudo -S nice -n -10 $HOME/bin/dtunnel --link node1.domain.com -local :7070 -clientkey verylongpasswd &
