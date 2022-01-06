#
# uitl functions for peekaboo modules
#
#
#

import os

WORKING_DIR = os.path.abspath('.')

MODULES_DIR = os.path.join(WORKING_DIR, 'modules')

LISTS_DIR = os.path.join(WORKING_DIR, 'lists')

# Pass in arr of strs that you want anwsers to
# ['target', 'port', 'val'...]
# prompts user with target = TypeTheAnwser
# returns as dict once finished

def select(keys):
    cmd_dict = {}
    i = 0
    while i < len(keys):
        try:
            key = keys[i]
            val = input(f'{key.capitalize()} = ')
            cmd_dict.update({key: val})
            i += 1
        except KeyboardInterrupt:
            break
    return cmd_dict


