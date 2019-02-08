#! /usr/bin/env python

################################################################################
#
# File:   mkfilter.py
# Date:   July 24, 2015
# Author: Fred Mota (fred.mota@keysight.com)
#
# History:
#  February 8, 2019:
#    - Updated copyright note.
#    - Use the ksvisionlib library.
#
# Description:
# This script creates 2^n filters, from 0 to 2^n-1.  Where the 0th filter
# contains all the source and destination IP addresses that when they are XORed
# together, the result is 0, the 1st filter conatins tall the source and
# destination IP addresses that when they are XORed together, the result is 1,
# and so on.
# The user can specify what type of IP addresses to use, IPv4 or IPv6, and also
# what bits to use in the IP addresses, that is, and offset from the least
# significant bit.
#
# For example, given:
# n (length) = 2
# version = IPv4
# offset = 0
#
# the script will create the following bidirectional filters:
#
#  0) IPv4 A= 0.0.0.0   IPv4 B= 0.0.0.0   Mask= 0.0.0.3   00 xor 00 = 00
#     IPv4 A= 0.0.0.1   IPv4 B= 0.0.0.1   Mask= 0.0.0.3   01 xor 01 = 00
#     IPv4 A= 0.0.0.2   IPv4 B= 0.0.0.2   Mask= 0.0.0.3   10 xor 10 = 00
#     IPv4 A= 0.0.0.3   IPv4 B= 0.0.0.3   Mask= 0.0.0.3   11 xor 11 = 00
#
#  1) IPv4 A= 0.0.0.1   IPv4 B= 0.0.0.0   Mask= 0.0.0.3   01 xor 00 = 01
#     IPv4 A= 0.0.0.3   IPv4 B= 0.0.0.2   Mask= 0.0.0.3   11 xor 10 = 01
#
#  2) IPv4 A= 0.0.0.2   IPv4 B= 0.0.0.0   Mask= 0.0.0.3   10 xor 00 = 10
#     IPv4 A= 0.0.0.3   IPv4 B= 0.0.0.1   Mask= 0.0.0.3   11 xor 01 = 10
#
#  3) IPv4 A= 0.0.0.3   IPv4 B= 0.0.0.0   Mask= 0.0.0.3   11 xor 00 = 11
#     IPv4 A= 0.0.0.2   IPv4 B= 0.0.0.1   Mask= 0.0.0.3   10 xor 01 = 11
#
# Note: If traffic with many different IP addresses is sent to these filters,
# the traffic should be load balanced evenly among the filters.
#
# COPYRIGHT 2015-2019 Keysight Technologies.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
################################################################################

import sys
import getopt
from ksvisionlib import *

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


nto = VisionWebApi(host=host, username=username, password=password, port=port)

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
