#!/bin/bash


echo -e "Copying flags to devices..."

flag_amt=$(ls | wc -l)

scp flags/victim_flag_1 debian@192.168.2.201:

scp flags/victim_flag_2 debian@192.168.2.202:/var/www/html/serv

scp flags/victim_flag_3 pi@192.168.2.203:


