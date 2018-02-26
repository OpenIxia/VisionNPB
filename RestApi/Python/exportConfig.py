#! /usr/bin/env python

#################################################################################
##
## File:   exportConfig.py
## Date:   May 24, 2017
## Author: Fred Mota (fmota@ixiacom.com)
##
## History:
##
## Description:
## This script will export the current configuration of an NTO or GSC device
## to a (.ata).
## The script will export the configuration of several hosts simultaneously to
## multiple files by creating one thread per host.
##
## (c) 1998-2017 Ixia. All rights reserved.
##
##############################################################################

import sys
import getopt
import threading
import time
from ixia_nto import *

def exportConfig(host_ip, port, username, password, timestamp):
    
    nto = NtoApiClient(host=host_ip, username=username, password=password, port=port)
    nto.exportConfig({'export_type': 'FULL_BACKUP', 'file_name': host_ip + '_full_backup_' + timestamp + '.ata'})

   

argv = sys.argv[1:]
username = ''
password = ''
host = ''
hosts_file = ''
config_file = ''
port = 8000

try:
    opts, args = getopt.getopt(argv,"u:p:h:f:r:", ["username=", "password=", "host=", "hosts_file=", "port="])
except getopt.GetoptError:
    print 'import_config.py -u <username> -p <password> [-h <host> | -f <host_file>] [-r port]'
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
    print 'exportConfig.py -u <username> -p <password> [-h <host> | -f <host_file>] [-r port]'
    sys.exit(2)

if password == '':
    print 'exportConfig.py -u <username> -p <password> [-h <host> | -f <host_file>] [-r port]'
    sys.exit(2)

if (host == '') and (hosts_file == ''):
    print 'exportConfig.py -u <username> -p <password> [-h <host> | -f <host_file>] [-r port]'
    sys.exit(2)

timestamp = time.strftime('%Y-%m-%d-%H-%M-%S')

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
    
    thread = threading.Thread(name=host, target=exportConfig, args=(host_ip, port, username, password, timestamp))
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
