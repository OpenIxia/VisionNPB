#! /usr/bin/env python

################################################################################
#
# File:   get_logs.py
# Date:   August 18, 2014
# Author: Fred Mota (fred.mota@keysight.com)
#
# History:
#  April 13, 2015:
#    - Started using the nto_pkg
#    - Added event handler for Ctrl-C
#  September 4, 2015:
#    - Use the new ixia_nto library
#    - Use the getSystemProperty instead of getSystem
#  February 8, 2019:
#    - Updated copyright note.
#    - Use the ksvisionlib library.
#
# Description:
# This script will retrieve the logs from a NTO/GSC device.  The script
# will collect the logs simultaneously from multiple hosts by creating
# one thread per host.
#
# COPYRIGHT 2014-2019 Keysight Technologies.
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
import time
import os
from ksvisionlib import *

def saveLogFiles(host_ip, host_name, port, username, password, timestamp):
    nto = VisionWebApi(host_ip, username, password, port)
    date = time.strftime("%Y-%m-%d")

    # Get the system type, GSC or NTO
    device_type = nto.getSystemProperty('type')
    if device_type == '7433':
        family_type = 'GSC'
    else:
        family_type = 'NTO'

    # If a directory doesn't exist for that host, create one
    if os.path.exists(host_name):
        if not os.path.isdir(host_name):
            print host_name + ' is not a directory.'
            return
    else:
        os.makedirs(host_name)

    # If a directory doesn't exist for the date under the host directory, create one
    if os.path.exists(host_name + '/' + date):
        if not os.path.isdir(host_name + '/' + date):
            print host_name + '/' + date + ' is not a directory.'
            return
    else:
        os.makedirs(host_name + '/' + date)

    # If the GSCLogs or NTOLogs directory doesn't exist, create it
    if os.path.exists(host_name + '/' + date + '/' + family_type + 'Logs'):
        if not os.path.isdir(host_name + '/' + date + '/' + family_type + 'Logs'):
            print host_name + + '/' + date + '/' + family_type + 'Logs is not a directory.'
            return
    else:
        os.makedirs(host_name + '/' + date + '/' + family_type + 'Logs')

    file_name = host_name + '/' + date + '/' + family_type + 'Logs/' + host_name + '-' + timestamp + '-' + 'logs.zip'
    nto.saveLogs({'file_name': file_name})

   

argv = sys.argv[1:]
username = ''
password = ''
host = ''
host_file = ''
port = 8000

try:
    opts, args = getopt.getopt(argv,"u:p:h:f:r:", ["username=", "password=", "host=", "file=", "port="])
except getopt.GetoptError:
    print 'get_logs.py -u <username> -p <password> [-h <hosts> | -f <host_file>] [-r <port>]'
    sys.exit(2)
for opt, arg in opts:
    if opt in ("-u", "--username"):
        username = arg
    elif opt in ("-p", "--password"):
        password = arg
    elif opt in ("-h", "--host"):
        host = arg
    elif opt in ("-f", "--file"):
        host_file = arg
    elif opt in ("-r", "--port"):
        port = arg

if username == '':
    print 'get_logs.py -u <username> -p <password> [-h <hosts> | -f <host_file>] [-r <port>]'
    sys.exit(2)

if password == '':
    print 'get_logs.py -u <username> -p <password> [-h <hosts> | -f <host_file>] [-r <port>]'
    sys.exit(2)

if (host == '') and (host_file == ''):
    print 'get_logs.py -u <username> -p <password> [-h <hosts> | -f <host_file>] [-r <port>]'
    sys.exit(2)

if (port == ''):
    print 'get_logs.py -u <username> -p <password> [-h <hosts> | -f <host_file>] [-r <port>]'
    sys.exit(2)

hosts_list = []
if (host_file != ''):
    f = open(host_file, 'r')
    for line in f:
        line = line.strip()
        hosts_list.append(line.split(' '))
    f.close()
else:
    hosts_list.append([host, host])

threads_list = []
for host in hosts_list:
    host_ip = host[0]
    host_name = host[1]
    timestamp = time.strftime('%Y-%m-%d-%H-%M-%S')
    
    thread = threading.Thread(name=host, target=saveLogFiles, args=(host_ip, host_name, port, username, password, timestamp))
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
