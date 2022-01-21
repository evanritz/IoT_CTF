#
# uitl functions for peekaboo modules
#
#
#

import subprocess
import socket

import os

WORKING_DIR = os.path.abspath('.')

MODULES_DIR = os.path.join(WORKING_DIR, 'modules')

LISTS_DIR = os.path.join(WORKING_DIR, 'lists')

BACKDOOR_PORT = 54111

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


