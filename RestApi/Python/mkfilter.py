#! /usr/bin/env python

import sys
import getopt
from ixia_nto import *

def ipAddress (bits, version):
    address = ''
    if version == 4:
        while len(bits) > 0:
            address = address + str(int(bits[0:8], 2)) + '.'
            bits = bits[8:]
    if version == 6:
        while len(bits) > 0:
            address = address + str(hex(int(bits[0:16], 2))[2:]) + ':'
            bits = bits[16:]

    address = address[:-1]
    return address


argv = sys.argv[1:]
username = ''
password = ''
host = ''
length = ''
offset = ''
version = ''
port = '8000'

try:
    opts, args = getopt.getopt(argv,"u:p:h:l:o:v:r:", ["username=", "password=", "host=", "length=", "offset=", "version=", "port="])
except getopt.GetoptError:
    print '0mkfilters.py -u <username> -p <password> -h <host> -l <length> -o <offset> -v <version> [-r <port>]'
    sys.exit(2)
for opt, arg in opts:
    if opt in ("-u", "--username"):
        username = arg
    elif opt in ("-p", "--password"):
        password = arg
    elif opt in ("-h", "--host"):
        host = arg
    elif opt in ("-l", "--length"):
        length = int(arg)
    elif opt in ("-o", "--offset"):
        offset = int(arg)
    elif opt in ("-v", "--version"):
        version = int(arg)
    elif opt in ("-r", "--port"):
        port = arg

if username == '':
    print '1mkfilters.py -u <username> -p <password> -h <host> -l <length> -o <offset> -v <version> [-r <port>]'
    sys.exit(2)

if password == '':
    print '2mkfilters.py -u <username> -p <password> -h <host> -l <length> -o <offset> -v <version> [-r <port>]'
    sys.exit(2)

if (host == ''):
    print '3mkfilters.py -u <username> -p <password> -h <host> -l <length> -o <offset> -v <version> [-r <port>]'
    sys.exit(2)

if length == '':
    print '4mkfilters.py -u <username> -p <password> -h <host> -l <length> -o <offset> -v <version> [-r <port>]'
    sys.exit(2)

if offset == '':
    print '5mkfilters.py -u <username> -p <password> -h <host> -l <length> -o <offset> -v <version> [-r <port>]'
    sys.exit(2)

if version == '':
    print '6mkfilters.py -u <username> -p <password> -h <host> -l <length> -o <offset> -v <version> [-r <port>]'
    sys.exit(2)


nto = NtoApiClient(host=host, username=username, password=password, port=port)

if version == 4:
    width = 32
else:
    width = 128

if length <= 0 or offset < 0 or length + offset > width:
    print ("Invalid length and offset specified.")

prefix = ''
fmt =  "{0:0" + str(width - length - offset) + "b}"
prefix = fmt.format(0)

postfix = ''
if offset > 0:
    fmt =  "{0:0" + str(offset) + "b}"
    postfix = fmt.format(0)

fmt = "{0:0" + str(length) + "b}"
mask = ipAddress(prefix + fmt.format(2**length - 1) + postfix, version)

for i in range(0, 2**length):
    address_sets = []
    for j in range(0, 2**length):
        for k in range(0, 2**length):
            if (((j ^ k) == i) and (j <= k)):
                address1 = ipAddress(prefix + fmt.format(j) + postfix, version)
                address2 = ipAddress(prefix + fmt.format(k) + postfix, version)
                address_sets.append({'addr_a': [address1 + "/" + mask], 'addr_b': [address2 + "/" + mask]})

    criteria = {'ipv' + str(version) +'_flow': {'address_sets': address_sets, 'flow_type': 'BIDI'}, 'logical_operation': 'AND'}
    #criteria['vlan'] = {'priority': None, 'vlan_id': '408,3400-3409,3701,3703-3704'}

    print (criteria)
    nto.createFilter({'mode': 'PASS_BY_CRITERIA', 'criteria': criteria, 'name': "XOR IPv" + str(version) + " " + fmt.format(i)})
