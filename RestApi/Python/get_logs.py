#! /usr/bin/env python3

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
#  October 18, 2021
#    - Change the script to Python 3.
#
# Description:
# This script will retrieve the logs from a NTO/GSC device.  The script
# will collect the logs simultaneously from multiple hosts by creating
# one thread per host.
#
# COPYRIGHT 2014-2021 Keysight Technologies.
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

CMD_SYNTAX = __file__ + " -u <username> -p <password> [-h <hosts> | -f <host_file>] [-r <port>]"

def saveLogFiles(host_ip, host_name, port, username, password, timestamp):
    nto = VisionWebApi(host=host_ip, username=username, password=password, port=port, timeout=400)
    date = time.strftime("%Y-%m-%d")

    # Get the system type, GSC or NTO
    device_type = nto.getSystemProperty('type')
    if device_type == "7433":
        family_type = "GSC"
    else:
        family_type = "NTO"

    # If a directory doesn't exist for that host, create one
    path = host_name
    if os.path.exists(path):
        if not os.path.isdir(path):
            print (f"{path} is not a directory.")
            return
    else:
        os.makedirs(host_name)

    # If a directory doesn't exist for the date under the host directory, create one
    path = f"{path}/{date}"
    if os.path.exists(path):
        if not os.path.isdir(path):
            print (f"{path} is not a directory.")
            return
    else:
        os.makedirs(host_name + '/' + date)

    # If the GSCLogs or NTOLogs directory doesn't exist, create it
    path = f"{path}/{family_type}Logs"
    if os.path.exists(path):
        if not os.path.isdir(path):
            print (f"{path} is not a directory.")
            return
    else:
        os.makedirs(path)

    file_name = f"{path}/{host_name}-{timestamp}-logs.zip"
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
    print (CMD_SYNTAX)
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
    print (CMD_SYNTAX)
    sys.exit(2)

if password == '':
    print (CMD_SYNTAX)
    sys.exit(2)

if (host == '') and (host_file == ''):
    print (CMD_SYNTAX)
    sys.exit(2)

if (port == ''):
    print (CMD_SYNTAX)
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
    timestamp = time.strftime("%Y-%m-%d-%H-%M-%S")
    
    thread = threading.Thread(name=host, target=saveLogFiles, args=(host_ip, host_name, port, username, password, timestamp))
    threads_list.append(thread)

for thread in threads_list:
    thread.daemon = True
    thread.start()

try:
    while threading.active_count() > 1:
        for thread in threads_list:
            thread.join(1)
        print (".", end = '', flush = True)
except KeyboardInterrupt:
    print ("Ctrl-c received! Sending kill to threads...")
    sys.exit()
print ("")
