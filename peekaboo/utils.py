#
# utils functions and consts for peekaboo modules
# 


import subprocess
import socket

import os

# dir consts
WORKING_DIR = os.path.abspath('.')

MODULES_DIR = os.path.join(WORKING_DIR, 'modules')

LISTS_DIR = os.path.join(WORKING_DIR, 'lists')

CAPTURES_DIR = os.path.join(WORKING_DIR, 'captures')

BACKDOOR_PORT = 54111

# for terminal coloring
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


# attempts TCP connection with backdoor port
# if port is open, connection will resolve, otherwise it will fail
def detect_backdoor(host):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    endpoint = (host.ip_addr, BACKDOOR_PORT)
    host.backdoor = not sock.connect_ex(endpoint)
    sock.close()

# linux command line ping
def do_ping(host):
    return do_advanced_command(['ping', '-c 1', host.ip_addr])

# linux command line hostnames
def get_hostnames():
    return do_simple_command(['hostname', '-I'])
    
# runs linux command, returns stdout
def do_simple_command(cmd):
    b_out = subprocess.check_output(cmd)
    return b_out.decode('UTF-8').strip()

# runs linux command, returns (stdout, stderr, exitcode)
def do_advanced_command(cmd):
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    b_out, b_err = proc.communicate()
    return (b_out.decode('UTF-8').strip(), b_err.decode('UTF-8').strip(), proc.returncode)

def wait_for_user_command(cmd):
    try:
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        while proc.poll() is None:
            print(proc.stdout.readline().decode('UTF-8').strip())
    except KeyboardInterrupt:
        print()
