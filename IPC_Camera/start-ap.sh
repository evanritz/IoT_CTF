#!/bin/sh
 
 #This script is expetected to be called from p2pcam
 
 ifconfig wlan0 up
 
 export PATH=$PATH:/home/ap:./
 
 # hack for test net wifi connection
 out=$(wpa_supplicant -B -c /home/ap/test_net.conf -i wlan0)
 
 if [ $? -ne 0 ]
 then
 
 	#ifconfig wlan0 up
 
 	#export PATH=$PATH:/home/ap:./
 
 
 
 	setup-hostap.sh wlan0 CLOUDCAM_$1
 	touch /tmp/dhcpd.leases
 	killall dhcpd; rm -f /var/run/dhcpd.pid
 	dhcpd -cf dhcpd.conf -lf /tmp/dhcpd.leases -pf /var/run/dhcpd.pid -4 wlan0
 
 else
 	udhcpc -i wlan0 
 fi
 
 echo $out > /home/ap/wpa_err.log
 