#!/usr/bin/env python3

################################################################################
#
# File:   mk_ip_csv.py
# Date:   October 4, 2024
# Author: Fred Mota (fred.mota@keysight.com)
#
# Description:
# Script to Create a Filter in a Network Packet Broker (NPB) from IP Network
# Addresses
#
# This Python script reads a list of IP network addresses (subnets) from a CSV
# file and generates a filter for a Network Packet Broker (NPB). The CSV file
# should contain a column of IP network addresses in CIDR notation
# (e.g., 192.168.1.0/24).
# The script parses the CSV, extracts the relevant addresses, and creates the
# necessary API calls or commands to configure the filter within the NPB system.
#
# Key functionalities:
#  - Reads and parses IP network addresses from a CSV file.
#  - Constructs a filter configuration to match the listed subnets.
#  - Sends the configuration to the NPB via API or CLI to set up the filter.
#
# This script is useful for automating the process of creating traffic filters
# based on a large number of network addresses without manual input, ensuring
# accuracy and efficiency.
#
# Requirements:
# - Python 3.x
# - CSV file containing IP network addresses in CIDR notation.
# - Access to the NPB's API or CLI for configuring filters.
# - The Python requests package
#
# Usage:
# python3 mk_ip_csv.py -u admin -p admin -a 192.168.29.132 -w 9000 -v 4 -i Examples.csv
#
# COPYRIGHT 2024 Keysight Technologies.
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
#################################################################################
import argparse
import ipaddress
from ksvisionlib import *

def get_args():

    parser = argparse.ArgumentParser(
        prog="mk_ip_csv",
        description="create IP filter - crete a dynamic filter containing IP addresses listed in a CSV file."
    )
    parser.add_argument(
        "-u",
        "--username",
        default="admin",
        required=False,
        dest="username",
        help="Username"
    )
    parser.add_argument(
        "-p",
        "--password",
        default="admin",
        required=False,
        dest="password",
        help="Password"
    )
    parser.add_argument(
        "-a",
        "--address",
        required=True,
        dest="host",
        help="NBP IP addresses"
    )
    parser.add_argument(
        "-w",
        "--web_api_port",
        default=8000,
        required=False,
        dest="port",
        help="Web API port"
    )
    parser.add_argument(
        "-i",
        "--input_file",
        default="att_ip.txt",
        required=False,
        dest="input",
        help="Input File"
    )
    parser.add_argument(
        "-v",
        "--version",
        default=4,
        required=False,
        dest="version",
        help="IP Version",
        type=int,
        choices={4, 6}
    )
    return parser.parse_args()


def main():
    # Parse the command line
    args = get_args()

    ip_list = []
    with open(args.input, 'r') as f:
        for line in f:
            line = line.strip()
            line = line.split(',')[0]

            # Comment
            if (line == '') or (line[0] == '#'):
                continue

            if args.version == 4:
                try:
                    ip_list.append(ipaddress.IPv4Network(line).exploded)
                except ValueError:
                    print (f'{line} is not a valid IPv4 address.')

            elif args.version == 6:
                try:
                    ip_list.append(ipaddress.IPv6Network(line).exploded)
                except ValueError:
                    print (f'{line} is not a valid IPv6 address.')

    ip_list.sort()
    #pprint.pprint (ip_list)

    # Connect to the NTO
    nto = VisionWebApi(host=args.host, port = args.port, username=args.username, password=args.password, debug=False)

    if args.version == 4:
        df_attrib = {"criteria": {
                         "ipv4_src_or_dst": [{"addr": ip_list}],
                         "logical_operation": "AND"},
                     "mode": "PASS_BY_CRITERIA"
                    }
    else:
        df_attrib = {"criteria": {
                         "ipv6_src_or_dst": [{"addr": ip_list}],
                         "logical_operation": "AND"},
                     "mode": "PASS_BY_CRITERIA"
                    }

    nto.createFilter(df_attrib)

    return


if __name__ == "__main__":
    main()
