


import shlex
import sys

sys.path.append('../')
from utils import CAPTURES_DIR, do_simple_command, do_advanced_command, wait_for_user_command, bcolors


class MQTT_AUTHENICATION_CRACKER:
    def name(self):
        return 'MQTT_AUTHENICATION_CRACKER'

    def selected(self, localhost, target):
        self.localhost = localhost
        self.target = target

        self.interface = None
        while self.interface == None:
            out = input('Enter the interface to sniff network traffic on: ')
            if out:
                self.interface = out

        self.sniff_cmd = f'sudo tcpdump -i {self.interface} -w {CAPTURES_DIR}/sniff_capture.pcap'

        self.parse_cmd = f'tshark -r {CAPTURES_DIR}/sniff_capture.pcap -Px -Y "mqtt"'

            
    def run(self):
        
        print(f'[!] {bcolors.HEADER}Starting MQTT Authencation Cracking{bcolors.ENDC}')
        print(f'[*] Starting Network Sniffing...\n')
        wait_for_user_command(self.sniff_cmd)
        print(f'\n[*] Stopping Network Sniffing')

        stdout, stderr, exit_code = do_advanced_command(shlex.split(self.parse_cmd))

        print('[*] Parsing Sniffed Network Traffic...')


        if stdout:
            print(f'[!] {bcolors.OKGREEN}MQTT Network Traffic detected!{bcolors.ENDC}')
            print(stdout)    
        else:
            print(f'[!] {bcolors.FAIL}No MQTT Network Traffic detected :({bcolors.ENDC}')
    
        

        
