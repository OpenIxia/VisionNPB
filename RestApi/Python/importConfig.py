#! /usr/bin/env python

#################################################################################
#
# File:   importConfig.py
# Date:   June 17, 2016
# Author: Fred Mota (fmota@ixiacom.com)
#
# History:
#  February 8, 2019:
#    - Updated copyright note.
#    - Use the ksvisionlib library.
#
# Description:
# This script will import a configuration (.ata) file to an NTO or an GSC
# device.
# The script will import the same configuration file simultaneously to multiple
# hosts by creating one thread per host.
#
# COPYRIGHT 2016-2019 Keysight Technologies.
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
import threading
from ksvisionlib import *

def importConfig(host_ip, port, username, password, config_file):
    
    nto = VisionWebApi(host=host_ip, username=username, password=password, port=port)
    nto.importConfig({'import_type': 'FULL_IMPORT_FROM_BACKUP', 'file_name': config_file})

   

argv = sys.argv[1:]
username = ''
password = ''
host = ''
hosts_file = ''
config_file = ''
port = 8000

try:
    opts, args = getopt.getopt(argv,"u:p:h:f:r:c:", ["username=", "password=", "host=", "hosts_file=", "port=", "config="])
except getopt.GetoptError:
    print 'importConfig.py -u <username> -p <password> -c <config_file> [-h <host> | -f <host_file>] [-r port]'
    sys.exit(2)
for opt, arg in opts:
    if opt in ("-u", "--username"):
        username = arg
    elif opt in ("-p", "--password"):
        password = arg
    elif opt in ("-h", "--host"):
        host = arg
    elif opt in ("-f", "--hosts_file"):
        hosts_file = arg
    elif opt in ("-r", "--port"):
        port = arg
    elif opt in ("-c", "--config"):
        config_file = arg

if username == '':
    print 'importConfig.py -u <username> -p <password> -c <config_file> [-h <host> | -f <host_file>] [-r port]'
    sys.exit(2)

if password == '':
    print 'importConfig.py -u <username> -p <password> -c <config_file> [-h <host> | -f <host_file>] [-r port]'
    sys.exit(2)

if (host == '') and (hosts_file == ''):
    print 'importConfig.py -u <username> -p <password> -c <config_file> [-h <host> | -f <host_file>] [-r port]'
    sys.exit(2)

if config_file == '':
    print 'importConfig.py -u <username> -p <password> -c <config_file> [-h <host> | -f <host_file>] [-r port]'
    sys.exit(2)

hosts_list = []
if (hosts_file != ''):
    f = open(hosts_file, 'r')
    for line in f:
        line = line.strip()
        if (line != '') and (line[0] != '#'):
            hosts_list.append(line.split(' '))
    f.close()
else:
    hosts_list.append([host, host])

threads_list = []
for host in hosts_list:
    host_ip = host[0]
    
    thread = threading.Thread(name=host, target=importConfig, args=(host_ip, port, username, password, config_file))
    threads_list.append(thread)

for thread in threads_list:
    thread.daemon = True
    thread.start()

try:
    while threading.active_count() > 1:
        for thread in threads_list:
            thread.join(1)
        sys.stdout.write('.')
        sys.stdout.flush()
except KeyboardInterrupt:
    print "Ctrl-c received! Sending kill to threads..."
    sys.exit()
print ""
