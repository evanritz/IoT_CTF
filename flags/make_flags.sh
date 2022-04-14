#!/bin/bash

flag_amt=$1
bsize=2048

echo -e "Generating $flag_amt flags...\n"

for (( i=1; i <= $flag_amt; i++ ))
do
    flag_src="flags_src/victim_flag_${i}_src"
    echo "Reading $bsize bytes from /dev/urandom to $flag_src"
    dd if=/dev/urandom of=$flag_src bs=${bsize} count=1 &> /dev/null
    echo "Creating md5 hash from $flag_src"
    flag=$(md5sum $flag_src | awk '{print $1}')
    echo $flag > flags/victim_flag_${i}
    echo -e "Flag created: $flag\n"
done

