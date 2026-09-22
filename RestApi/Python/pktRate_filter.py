#! /usr/bin/env python3

#################################################################################
##
## File:   pktRate_filter.py
## Date:   June 26, 2016
## Author: Fred Mota (fmota@ixiacom.com)
## Edits:  Cameron Pepe (cpepe@ixiacom.com)
##
## History:
## Fred Mota wrote the logic of the script using bandwidth utilization as
## the monitored statistic. Cameron Pepe altered the script to monitor the
## inspected packet rate.
##
## Description:
## This script will connect or disconnect one network port to or from a dynamic
## filter depending on the inspected packet rate of the of the port group that
## is connected to the dynamic filter.
## The three items, the network ports, the dynamic filter, and the tool port
## group will be identified with a common keyword.
##
## There are two ways to specify the target NTO where the connections will be
## modified.  This first is by providing the IP address of the host as an input
## to the script using the -h option.  The second methods is to provide the name
## of a file that contains one or more IP addresses.  The file doesn't have to
## follow any particular format.  The only requirement is that the IPv4 or IPv6
## addresses should be delimited by spaces.  Anything after a '#' sign in a
## line will be ignored.
##
## (c) 1998-2016 Ixia. All rights reserved.
##
#################################################################################

import sys
import getopt
import threading
import time
from ksvisionlib import *

KEYWORD = 'TIME'
ITERATIONS = 2
SECS_PER_ITERATION = 1
RATE_HIGH_LIMIT = 30000
RATE_LOW_LIMIT  = 30000


def setFilter(host_ip, port, username, password):

    # Connect to the NTO
    nto = VisionWebApi(host=host_ip, username=username, password=password, port=port)

    # This piece of the code only works with NTO v4.4 or later
    # It is more elegant and efficient than the block below
    #
    # Find all the network ports that don't belong to any port group
    # with the specific keyword
    controlled_network_ports = []
    for network_port in nto.searchPorts({'mode': 'NETWORK', 'port_group_id': None}):
        keywords = nto.getPortProperty(str(network_port['id']), 'keywords')
        if KEYWORD in keywords:
            controlled_network_ports.append(network_port['id'])

    # Find all the network ports that don't belong to any port group
    # with the specific keyword
    controlled_network_ports = []
    for network_port in nto.searchPorts({'mode': 'NETWORK'}):
        keywords = nto.getPortProperty(str(network_port['id']), 'keywords')
        if KEYWORD in keywords:
            if not nto.getPortProperty(str(network_port['id']), 'port_group_id'):
                controlled_network_ports.append(network_port['id'])

    # Find all the network port groups with the specific keyword
    controlled_network_port_groups = []
    for network_port_groups in nto.searchPortGroups({'mode': 'NETWORK'}):
        keywords = nto.getPortGroupProperty(str(network_port_groups['id']), 'keywords')
        if KEYWORD in keywords:
            controlled_network_port_groups.append(network_port_groups['id'])

    # Find the first dynamic filter with the specific keyword
    controlled_filter = ''
    for filter in nto.getAllFilters():
        keywords = nto.getFilterProperty(str(filter['id']), 'keywords')
        if KEYWORD in keywords:
            controlled_filter = str(filter['id'])
            break

    # Find the first tool port group with the specific keyword
    controlled_tool_port_group = ''
    for port_group in nto.searchPortGroups({'mode': 'TOOL'}):
        keywords = nto.getPortGroupProperty(str(port_group['id']), 'keywords')
        if KEYWORD in keywords:
            controlled_tool_port_group = str(port_group['id'])
            break

    # If unable to find at least a network port, a dynamic filter, or a tool port
    # group containing the keyword, don't do anything
    if (((len(controlled_network_ports) == 0) and (len(controlled_network_port_groups) == 0)) or (controlled_filter == '') or (controlled_tool_port_group == '')):
        print (time.strftime("%a %b %d %H:%M:%S %Z %Y") + ': Keyword is missing from the configuration.')
        return

    # Periodically, take a number of tool port group inspected packets rate samples
    # and compute the average
    ofile = open(os.path.dirname(os.path.realpath(__file__)) + '/' + os.path.splitext(os.path.basename(__file__))[0] + '_' + host_ip + '.txt', 'a')
    ofile.write(time.strftime("%a %b %d %H:%M:%S %Z %Y"))
    ofile.write(': ')

    pkt_rate_sum = 0
    for i in range(ITERATIONS):
        stats_snapshot = nto.getStats({'stat_name': 'tp_current_insp_rate_packets', 'port_group': controlled_tool_port_group})
        pkt_rate = stats_snapshot['stats_snapshot'][0]['tp_current_insp_rate_packets']
        pkt_rate_sum += pkt_rate
        time.sleep(SECS_PER_ITERATION)

        ofile.write('{0:7d}'.format(pkt_rate))
        ofile.write(' ')
        
    pkt_rate_avg = float(pkt_rate_sum) / ITERATIONS
    ofile.write('   Avg= ' + '{0:10.2f}'.format(pkt_rate_avg))

    filter_changed = False

    # If the average packet rate is greater than the high limit,
    # disconnect one of the network ports from the dynamic filter
    if pkt_rate_avg > RATE_HIGH_LIMIT:
        source_port_groups = nto.getFilterProperty(controlled_filter, 'source_port_group_list')
        for network_port_group in controlled_network_port_groups:
            if network_port_group in source_port_groups:
                source_port_groups.remove(network_port_group)
                nto.modifyFilter(controlled_filter, {'source_port_group_list' : source_port_groups})
                filter_changed = True
                ofile.write('   => Disconnected Network Port Group ')
                ofile.write(nto.getPortGroupProperty(str(network_port_group), 'name'))
                break

        if not filter_changed:
            source_ports = nto.getFilterProperty(controlled_filter, 'source_port_list')
            for network_port in controlled_network_ports:
                if network_port in source_ports:
                    source_ports.remove(network_port)
                    nto.modifyFilter(controlled_filter, {'source_port_list' : source_ports})
                    filter_changed = True
                    ofile.write('   => Disconnected Network Port ')
                    ofile.write(nto.getPortProperty(str(network_port), 'name'))
                    break

    # If the average packet rate is less than the low limit,
    # connect one of the network ports to the dynamic filter
    elif pkt_rate_avg < RATE_LOW_LIMIT:
        source_port_groups = nto.getFilterProperty(controlled_filter, 'source_port_group_list')
        for network_port_group in controlled_network_port_groups:
            if network_port_group not in source_port_groups:
                source_port_groups.append(network_port_group)
                nto.modifyFilter(controlled_filter, {'source_port_group_list' : source_port_groups})
                filter_changed = True
                ofile.write('   => Connected Network Port Group ')
                ofile.write(nto.getPortGroupProperty(str(network_port_group), 'name'))
                break

        if not filter_changed:
            source_ports = nto.getFilterProperty(controlled_filter, 'source_port_list')
            for network_port in controlled_network_ports:
                if network_port not in source_ports:
                    source_ports.append(network_port)
                    nto.modifyFilter(controlled_filter, {'source_port_list' : source_ports})
                    filter_changed = True
                    ofile.write('   => Connected Network Port ')
                    ofile.write(nto.getPortProperty(str(network_port), 'name'))
                    break

    ofile.write('\n')
    ofile.close()

    return


# Main program

argv = sys.argv[1:]
username = ''
password = ''
host = ''
hosts_file = ''
port = 8000

try:
    opts, args = getopt.getopt(argv,"u:p:h:f:r:", ["username=", "password=", "host=", "hosts_file=", "port="])
except getopt.GetoptError:
    print ('pktRate_filter.py -u <username> -p <password> [-h <hosts> | -f <host_file>] [-r port]')
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

if username == '':
    print ('pktRate_filter.py -u <username> -p <password> [-h <hosts> | -f <host_file>] [-r port]')
    sys.exit(2)

if password == '':
    print ('pktRate_filter.py -u <username> -p <password> [-h <hosts> | -f <host_file>] [-r port]')
    sys.exit(2)

if (host == '') and (hosts_file == ''):
    print ('pktRate_filter.py -u <username> -p <password> [-h <hosts> | -f <host_file>] [-r port]')
    sys.exit(2)

# Create a list whith all the hosts
hosts_list = []
if (hosts_file != ''):
    f = open(hosts_file, 'r')
    for line in f:
        line = line.strip()
        item_list = line.split(' ')
        for item in item_list:
            if (item != '') and (item[0] == '#'):
                break
            hosts_list.append(item)
    #print (hosts_list)
    f.close()
else:
    hosts_list.append(host)

# Create and lunch a thread for every host
threads_list = []
for host in hosts_list:
    thread = threading.Thread(name=host, target=setFilter, args=(host, port, username, password))
    threads_list.append(thread)

for thread in threads_list:
    thread.daemon = True
    thread.start()

# Wait until every thread finishes
try:
    while threading.active_count() > 1:
        for thread in threads_list:
            thread.join(1)
        #print ('.', end="", flush=True)
except KeyboardInterrupt:
    print ("Ctrl-c received! Sending kill to threads...")
    sys.exit()
