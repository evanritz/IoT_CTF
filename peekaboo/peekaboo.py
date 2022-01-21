# peekaboo.py
#
# This is the Peekaboo Launcher
# Peekaboo is shitty clone of msfvenom launcher/loader/interface
# To run peekaboo you MUST provide a nmap scan file in XML as an argument
# e.g python3 peekaboo.py capture.xml
#
# peekaboo can load modules during runtime with the command "reload modules"
#
# Peekaboo checks these dirs for files:
# modules/
# lists/
# backdoor/
# 
# modules/ - Peekaboo modules are defined by these requirments:
# modules MUST be named something descriptive
# modules define a class within that is the same name as the .py file ALL uppercase
# function name() - returns the name of the class as a string ALL uppercase
# function selected() - inits needed variables, loads files, etc, stuff that can be done before running an exploit/attack
# function run() - runs the exploit/attack code, returns True if successful, False if failed
# TODO: optional function infect() - drops backdoor binary on device and executes
#
# list/ - Holds username/password lists that can be used for modules
# import the list dir from utils.py
#
# backdoor/ - Holds compiled binarys of backdoors that can be dropped on to a target device
# ! http server has to been added to module to do this !
# import the backdoor dir from utils.py
#
# Current commands for Peekaboo:
#
# ! Target commands !
# - lists targets
#       lists targets for the nmap scan file in ordered list
#       
# - select target <arg1>
#       selects target from nmap scan file
#       arg1: can be idx from ordered list or ip addr
#
# - info target <arg1>
#       lists port scan of selected target
#       arg1: can be idx from ordered list or ip addr or none if target already selected
#
# - session target
#       target MUST be selected already
#       if target has a backdoor on BACKDOOR_PORT, will connect to backdoor shell        
#
# ! Module commands !
# - list modules
#       lists modules currently loaded in ordered list
#
# - reload modules
#       reloads modules for MODULES dir
#
# - select module <arg1>
#       selects module from currently loaded modules
#       arg1: can be idx from ordered list or MODULE_NAME
#
# - run module
#       module MUST be selected already
#       Will run selected module on selected target
#
# ! Misc commands !
# - help
#       prints this text
#
# Written by Evan and Richard

import subprocess
import sys
import xmltodict
import socket
import os
import telnetlib

from utils import *

PROG_NAME = 'Peekaboo'

# selected target
TARGET = None

LOCALHOST = None

# selected module
MODULE = None
# loaded modules dict
MODULES = {}

# data obj for parsing XML nmap scan file 
class Host:
    def __init__(self, host_dict):
        self.ip_addr = host_dict['address']['@addr']
        self.online = False
        self.backdoor = False
        self.ports = []

        try:
            ports_dict = host_dict['ports']['port']
            if not isinstance(ports_dict, list):
                ports_dict = [ports_dict]

            for port_dict in ports_dict:
                self.ports.append(Port(port_dict))
        except: 
            pass
            
class Port:
    def __init__(self, port_dict):
        self.number = port_dict['@portid']
        self.protocol = port_dict['@protocol']
        self.state = port_dict['state']['@state']
        self.service = port_dict['service']['@name']

# loads modules from MODULES dir and repopulates MODULES dict
def load_modules():

    module_files = os.listdir(MODULES_DIR)
    module_names = []

    # only grab .py files
    for module_file in module_files:
        module_name, ext = os.path.splitext(module_file)
        if ext == '.py':
            module_names.append(module_name)
        
    # look at MODULES dir for files
    sys.path.append(MODULES_DIR)

    print(f'Detecting Modules...')

    global MODULES
    global MODULE
    MODULES = {}

    # try to load module files from MODULES dir
    for module_name in module_names:
        print(f'Trying to load ({module_name}) Module?: ', end='')
        try:
            if module_name in sys.modules:
                del sys.modules[module_name]
            module = __import__(module_name)
            mclass = getattr(module, module_name.upper())
            MODULES.update({module_name.upper(): mclass})
            if MODULE != None:
                if MODULE.name() == module_name.upper():
                    # inits module obj from class def
                    MODULE = mclass()

            print(f'{bcolors.OKGREEN}Loaded{bcolors.ENDC}')
        except Exception as e:
            print(f'{bcolors.FAIL}Failed{bcolors.ENDC}')
            print(e)

    print(f'Detected {len(module_names)} Modules, Loaded {len(MODULES.keys())} Modules')


# debug function
#def test_module():
#    global MODULE    
#    MODULE.test_func()

def do_nothing():
    pass

def list_targets(hosts):
    print('{: <15} {: <15} {: <15}'.format('IDX', 'Host', 'Backdoored?'))
    for num, host in enumerate(hosts):
        if host.backdoor:
            print('{: <15} {: <15} {: <15}'.format(num+1, host.ip_addr, f'{bcolors.OKGREEN}Yes{bcolors.ENDC}'))
        else:
            print('{: <15} {: <15} {: <15}'.format(num+1, host.ip_addr, f'{bcolors.FAIL}No{bcolors.ENDC}'))

def list_modules():
    global MODULES
    print('{: <15} {: <15}'.format('IDX', 'Module'))
    for num, module_name in enumerate(MODULES.keys()):
        print('{: <15} {: <15}'.format(num+1, module_name))

def select_target(hosts, args):

    # select either a list num or ip addr for target
    # must be from list
    # vaildate num or ip

    if len(args) > 1:
        print(f'[!] {bcolors.FAIL}Remove unneeded arguments...{bcolors.ENDC}')
        print(f'[!] {bcolors.FAIL}Nothing was selected{bcolors.ENDC}')
    elif len(args) < 1:
        print(f'[!] {bcolors.FAIL}Must specify list number or ip address for target...{bcolors.ENDC}')
        print(f'[!] {bcolors.FAIL}Nothing was selected{bcolors.ENDC}')
    else:
        target = args[0]
        target_host = None
        # smallest (in terms of length) ip is 0.0.0.0, 1.1.1.1, etc
        if target.count('.') == 3 and len(target) >= 7:
            for host in hosts:
                if host.ip_addr == target:
                    target_host = host
        elif target.count('.') == 0:
            try:
                num = int(target)-1
                if num >= 0 and num < len(hosts):
                    target_host = hosts[num]
            except ValueError:
                pass
                    
        if target_host != None:
            global TARGET
            TARGET = target_host
        else:
            print(f'[!] {bcolors.FAIL}Invaild input{bcolors.ENDC}')
            print(f'[!] {bcolors.FAIL}Nothing was selected{bcolors.ENDC}')

def select_module(args):
     
    global MODULES
    global TARGET

    if TARGET == None:
        print(f'[!] {bcolors.FAIL}Target has not be selected...{bcolors.ENDC}')
        print(f'[!] {bcolors.FAIL}Nothing was selected{bcolors.ENDC}')
    elif len(args) > 1:
        print(f'[!] {bcolors.FAIL}Remove unneeded arguments...{bcolors.ENDC}')
        print(f'[!] {bcolors.FAIL}Nothing was selected{bcolors.ENDC}')
    elif len(args) < 1:
        print(f'[!] {bcolors.FAIL}Must specify idx number or module name...{bcolors.ENDC}')
        print(f'[!] {bcolors.FAIL}Nothing was selected{bcolors.ENDC}')
    else:
        module_selector = args[0]
        selected_module = None
        try:
            num = int(module_selector)-1       
            if num >= 0 and num < len(MODULES):
                key = list(MODULES.keys())[num]
                selected_module = MODULES[key]
        except ValueError:
            for key in MODULES.keys():
                if module_selector == key:
                    selected_module = MODULES[key]
                
        if selected_module != None:
            global MODULE
            MODULE = selected_module()
        else:
            print(f'[!] {bcolors.FAIL}Invaild input{bcolors.ENDC}')
            print(f'[!] {bcolors.FAIL}Nothing was selected{bcolors.ENDC}')

def session_target():
    
    global TARGET
    if TARGET == None:
        print(f'[!] {bcolors.FAIL}No target to connect to...{bcolors.ENDC}')
    elif TARGET != None and not TARGET.backdoor:
        print(f'[!] {bcolors.FAIL}Target has no backdoor...{bcolors.ENDC}')
    else:
        # spawns basic telnet terminal session from the backdoor
        with telnetlib.Telnet(TARGET.ip_addr, BACKDOOR_PORT) as tn:
            tn.interact()
            tn.close()
        
def info_target(hosts, args):
    
    # info either a list num or ip addr or already selected target

    global TARGET
    target_host = None

    if len(args) == 0 and TARGET != None:
        target_host = TARGET
    elif len(args) == 0 and TARGET == None:
        # err
        print(f'[!] {bcolors.FAIL}No selected target or argument was passed. Must specify list num, ip addr, or already selected target{bcolors.ENDC}')
    elif len(args) > 1:
        # err
        print(f'[!] {bcolors.FAIL}Remove unneeded arugments{bcolors.ENDC}')
    else:
        target = args[0]
        # smallest (in terms of length) ip is 0.0.0.0, 1.1.1.1, etc
        if target.count('.') == 3 and len(target) >= 7:
            for host in hosts:
                if host.ip_addr == target:
                    target_host = host
        elif target.count('.') == 0:
            try:
                num = int(target)-1
                if num >= 0 and num < len(hosts):
                    target_host = hosts[num]
            except ValueError:
                pass
                    
    if target_host != None:
        print(f'Host ({target_host.ip_addr})')
        print('{: <15} {: <15} {: <15} {: <15}'.format('Port', 'Protocol', 'State', 'Service'))
        for port in target_host.ports:
            print('{: <15} {: <15} {: <15} {: <15}'.format(port.number, port.protocol, port.state, port.service))
    else:
        print(f'[!] {bcolors.FAIL}Invaild input{bcolors.ENDC}')
    
    
def run_module():
    global MODULE
    global TARGET
    global LOCALHOST
    
    # confirm TARGET and MODULE have been selected
    if TARGET != None and MODULE != None:
        try:
            # inits and runs module
            MODULE.selected(LOCALHOST, TARGET)
            MODULE.run()
        except Exception as e:
            print(e)
    else:
        print('[!] {bcolors.FAIL}Module and Target must be selected...{bcolors.ENDC}')

def peekaboo_banner():

    banner = '''
                 _         _                 
 _ __   ___  ___| | ____ _| |__   ___   ___  
| '_ \ / _ \/ _ \ |/ / _` | '_ \ / _ \ / _ \ 
| |_) |  __/  __/   < (_| | |_) | (_) | (_) |
| .__/ \___|\___|_|\_\__,_|_.__/ \___/ \___/ 
|_|                                          

    '''
    
    print(banner)

def peekaboo_help():
    info = '''

# Current commands for Peekaboo:
#
# ! Target commands !
# - lists targets
#       lists targets for the nmap scan file in ordered list
#       
# - select target <arg1>
#       selects target from nmap scan file
#       arg1: can be idx from ordered list or ip addr
#
# - info target <arg1>
#       lists port scan of selected target
#       arg1: can be idx from ordered list or ip addr or none if target already selected
#
# - session target
#       target MUST be selected already
#       if target has a backdoor on BACKDOOR_PORT, will connect to backdoor shell        
#
# ! Module commands !
# - list modules
#       lists modules currently loaded in ordered list
#
# - reload modules
#       reloads modules for MODULES dir
#
# - select module <arg1>
#       selects module from currently loaded modules
#       arg1: can be idx from ordered list or MODULE_NAME
#
# - run module
#       module MUST be selected already
#       Will run selected module on selected target
#
# ! Misc commands !
# - help
#       prints this text

    '''
    
    print(info)

def main():

    if len(sys.argv) != 2:
        print(f'[!] {bcolors.FAIL}Nmap scan needed{bcolors.ENDC}')
        sys.exit(1)

    # reads file from sys arguments
    XML_nmap_capture_file = sys.argv[1]
        
    # open XML nmap scan file and parse into dict using xmltodict lib
    with open(XML_nmap_capture_file, 'r') as f:
        XML_nmap_capture_data = xmltodict.parse(f.read())

    # pull out needed data
    nmap_capture = XML_nmap_capture_data['nmaprun']
    nmap_capture_hosts = nmap_capture['host']

    hosts = []
    parsed_host_amt = 0

    # checks for online hosts, init host obj to serialize data, and adds to hosts arr
    for host in nmap_capture_hosts:
        if host['status']['@state'] == 'up':
            hosts.append(Host(host))
            parsed_host_amt += 1    
    
    user_cmd = None

    cmd_dict = {
        ('list', 'targets'): 'list_targets(hosts)',
        ('select', 'target'): 'select_target(hosts, args)',
        ('info', 'target'): 'info_target(hosts, args)',
        ('reload', 'modules'): 'load_modules()',
        # ('test', 'module'): 'test_module()',
        ('list', 'modules'): 'list_modules()',
        ('select', 'module'): 'select_module(args)',
        ('run', 'module'): 'run_module()',
        ('session', 'target'): 'session_target()',
        ('help', ): 'peekaboo_help()',
        (): 'do_nothing()'
    }

    peekaboo_banner()

    # grab localhost hostnames from assigned interfaces
    hostnames_str = get_hostnames()
    hostnames = hostnames_str.split()

    print(f'Your Hostnames are: {bcolors.HEADER}{hostnames_str}{bcolors.ENDC}\n')

    # load modules on init
    load_modules()

    print()

    print(f'Using NMAP XML file: {XML_nmap_capture_file}')    
    print(f'Parsed {parsed_host_amt} hosts from {XML_nmap_capture_file}')

    # removes localhost from hosts arr and sets to LOCALHOST
    for host in hosts:
        for hostname in hostnames:
            if host.ip_addr == hostname:
                print(f'{bcolors.WARNING}Removed Localhost ({host.ip_addr}) from Hosts{bcolors.ENDC}')
                parsed_host_amt -= 1
                hosts.remove(host)
                global LOCALHOST
                LOCALHOST = host
    print()

    # pings each online host from XML nmap scan file
    print('Pinging each Host to confirm online status...')

    up_host_amt = 0

    for host in hosts:
        print(f'Is Host ({host.ip_addr}) Up?: ', end='')
        out, err, code = do_ping(host)
        if not code:
            print(f'{bcolors.OKGREEN}Yes{bcolors.ENDC}')
            host.online = True
            up_host_amt += 1
        else:
            print(f'{bcolors.FAIL}No{bcolors.ENDC}')
        
    print(f'Pinged {parsed_host_amt} Hosts, {up_host_amt} hosts responded\n')

    
    # checks for backdoor port on hosts that responded to ping
    print(f'Detecting existing Backdoors (PORT: {BACKDOOR_PORT}) on online Hosts...')

    bd_host_amt = 0

    for host in hosts:
        if host.online:
            print(f'Is Host ({host.ip_addr}) Backdoored?: ', end='')
            detect_backdoor(host)
            if host.backdoor:
                print(f'{bcolors.OKGREEN}Yes{bcolors.ENDC}')
                bd_host_amt += 1
            else:
                print(f'{bcolors.FAIL}No{bcolors.ENDC}')
    
    if bd_host_amt == 0:
        print('No Hosts are Backdoored :(\n')
    else:
        print(f'{bd_host_amt} Hosts are Backdoored!\n')
            
    # takes user input from terminal interface
    while user_cmd == None:
        try:

            cmd_cursor = f'{PROG_NAME} >> '

            if TARGET != None:
                cmd_cursor = f'{PROG_NAME} {bcolors.OKBLUE}T({TARGET.ip_addr}){bcolors.ENDC} >> '       

            if TARGET != None and MODULE != None:
                cmd_cursor = f'{PROG_NAME} {bcolors.OKBLUE}T({TARGET.ip_addr}){bcolors.ENDC} {bcolors.OKGREEN}M({MODULE.name()}){bcolors.ENDC} >> ' 
       
            # parse out command and arguments, match to cmd_dict, and eval the matched function
            user_cmd = input(cmd_cursor).split()
            user_cmd = tuple(user_cmd)
            
            cmd = user_cmd[0:2]
        
            args = user_cmd[2:len(user_cmd)]
 
            if cmd in cmd_dict.keys():
     
                out = cmd_dict[cmd]
                
                eval(out)
            
            else: 
                print(f'[!] {bcolors.FAIL}Unknown Command :( Type help for a list of available commands{bcolors.END}')

            user_cmd = None        

        except KeyboardInterrupt:
            print('\nQuiting...')
            break


if __name__ == '__main__':
    main()













