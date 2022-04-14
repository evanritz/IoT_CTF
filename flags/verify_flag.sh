#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

flag=$1

echo -e "Comparing md5 hash with src files...\n"

flag_amt=$(ls flags_src | wc -l)

found_hash=0
for (( i=1; i<=$flag_amt; i++ ))
do
    flag_src="flags_src/victim_flag_${i}_src"
    md5_hash=$(md5sum $flag_src | awk '{print $1}')
    echo -n "Checking $flag_src?"
    if [ "$flag" == "$md5_hash" ]
    then
        echo -e "$GREEN SAME $NC"
        found_hash=1
    else
        echo -e "$RED NOT SAME $NC"
    fi
done

if [ $found_hash -eq 1 ]
then
    echo -e "\n${GREEN}HASH FOUND! $NC"
else
    echo -e "\n${RED}No hash found :( $NC"
fi


