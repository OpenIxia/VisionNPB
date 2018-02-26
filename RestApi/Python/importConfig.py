#! /usr/bin/env python

#################################################################################
##
## File:   importConfig.py
## Date:   June 17, 2016
## Author: Fred Mota (fmota@ixiacom.com)
##
## History:
##
## Description:
## This script will import a configuration (.ata) file to an NTO or an GSC
## device.
## The script will import the same configuration file simultaneously to multiple
## hosts by creating one thread per host.
##
## (c) 1998-2016 Ixia. All rights reserved.
##
##############################################################################

import sys
import getopt
import threading
from ixia_nto import *

def importConfig(host_ip, port, username, password, config_file):
    
    nto = NtoApiClient(host=host_ip, username=username, password=password, port=port)
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
