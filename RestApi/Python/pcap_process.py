#! /usr/bin/env python3

#################################################################################
#
# File:   pcap_anonymize.py
# Date:   October 21, 2021
# Author: Fred Mota (fred.mota@keysight.com)
#
# History:
#
# Description:
# This script will anonymized all the IMSIs included in all the GTPv1, GTPv2,
# PFCP, and DIAMETER packets captured in a PCAP file.
#
# COPYRIGHT 2021 Keysight Technologies.
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
from scapy.all import *
from scapy.layers.inet6 import *
from scapy.layers.vxlan import *
from scapy.contrib.mpls import *
from scapy.contrib.gtp import *
from scapy.contrib.gtp_v2 import *
from scapy.contrib.pfcp import *
from scapy.contrib.diameter import *
import gtp_contrib_ext
import FpGwMsg_pb2
import getopt
import sys
import struct
import binascii
import math
import random
from itertools import chain
import io

CMD_SYNTAX = __file__ + " -i <input_file> -o <output_file>"
FCS_LENGTH = 4
FRAGMENT_TIMEOUT = 5 # in seconds

# DIAMETER
DIAMETER_AVP_SUBSCRIPION_ID         = 443
DIAMETER_AVP_END_USER_E164          = 0
DIAMETER_AVP_END_USER_IMSI          = 1
DIAMETER_AVP_USER_EQUIPMENT_INFO_ID = 458
DIAMETER_AVP_IMEISV                 = 0

# AFFIRMED NETWORKS
AFFIRMED_ENTERPRISE_ID                        = 37963
AFFIRMED_PFCP_SESSION_ESTABLISHMENT_REQUEST   = 32983
AFFIRMED_PFCP_SESSION_MODIFICATION_REQUEST    = 32985
AFFIRMED_MSG_TYPE_WfSessionMcdTableFullSchema = 201
AFFIRMED_MAGIC_STRING = b'\xbe\xad\xfe\xed'

# Payloads
PAYLOAD_LAYERS_LIST = [gtp.GTPHeader,
                       GTPHeader,
                       IP,
                       IPv6,
                       IPv6ExtHdrDestOpt,
                       IPv6ExtHdrFragment,
                       IPv6ExtHdrHopByHop,
                       IPv6ExtHdrRouting,
                       IPv6ExtHdrSegmentRouting,
                       IPv6ExtHdrSegmentRoutingTLV,
                       IPv6ExtHdrSegmentRoutingTLVEgressNode,
                       #IPv6ExtHdrSegmentRoutingTLVHMAC,
                       IPv6ExtHdrSegmentRoutingTLVIngressNode,
                       #IPv6ExtHdrSegmentRoutingTLVPad1,
                       #IPv6ExtHdrSegmentRoutingTLVPadN,
                       IPv6ExtHdrSegmentRoutingTLVPadding,
                       TCP,
                       UDP]

IPV6_EXT_HDRS = [IPv6ExtHdrDestOpt,
                 IPv6ExtHdrFragment,
                 IPv6ExtHdrHopByHop,
                 IPv6ExtHdrRouting,
                 IPv6ExtHdrSegmentRouting,
                 IPv6ExtHdrSegmentRoutingTLV,
                 IPv6ExtHdrSegmentRoutingTLVEgressNode,
                 #IPv6ExtHdrSegmentRoutingTLVHMAC,
                 IPv6ExtHdrSegmentRoutingTLVIngressNode,
                 #IPv6ExtHdrSegmentRoutingTLVPad1,
                 #IPv6ExtHdrSegmentRoutingTLVPadN,
                 IPv6ExtHdrSegmentRoutingTLVPadding]

flatten = chain.from_iterable
LEFT, RIGHT = 1, -1

def join_ranges(data, offset=0):
    ranges_list = []
    data = sorted(flatten(((start, LEFT), (stop + offset, RIGHT)) for start, stop in data))
    c = 0
    for value, label in data:
        if c == 0:
            x = value
        c += label
        if c == 0:
            ranges_list.append((x, value - offset))
    return ranges_list

class FragPkt(object):
    def __init__(self, timestamp, first, last, payload, mf):
        self.__ranges = [(first, last)]
        self.__timestamp = timestamp
        self.__last_byte = None
        if not mf:
            self.__last_byte = last

        self.__buffer=io.BytesIO()
        self.__buffer.seek(first)
        self.__buffer.write(payload)

    def __str__(self):
        return f"FragPkt(ranges={self.__ranges}, timestamp={self.__timestamp}, last_byte={self.__last_byte})"

    def __repr__(self):
        return str(self)

    def add_fragment(self, timestamp, first, last, payload, mf):
        if (timestamp - self.__timestamp) > FRAGMENT_TIMEOUT:
            self.__init__(timestamp, first, last, payload, mf)
        else:
            if not mf:
                self.__last_byte = last
            self.__timestamp = timestamp
            self.__ranges.append((first, last))
            self.__ranges = join_ranges(self.__ranges, 2)

            self.__buffer.seek(first)
            self.__buffer.write(payload)

    def fragment_completed(self):
        return self.__last_byte and len(self.__ranges) == 1 and self.__ranges[0][0] == 0 and self.__ranges[0][1] == self.__last_byte

    def get_payload(self):
        return self.__buffer.getvalue()

class PcapRandId(object):
    def __init__(self, keep):
        self.__id_dict = {}
        self.__keep = keep

    def _getRandomId(self, id, length):

        id_str = str(id)
        low_1  = int(id_str[:self.__keep] + '0' * (len(id_str) - self.__keep))
        high_1 = int(id_str[:self.__keep] + '9' * (len(id_str) - self.__keep))

        if id >= 0 and id <= 2 ** 7 - 1:
            low_2  = 0
            high_2 = 2 ** 7 - 1
        else:
            low_2  = 2 ** ((math.log(id, 2) // 7) * 7)
            high_2 = 2 ** ((math.log(id, 2) // 7 + 1) * 7)

        low  = max(low_1,  low_2)
        high = min(high_1, high_2)

        if low >= high:
            print(f"No suitable substitution for ID = {id}.")
            sys.exit(2)

        count = 0

        while True:
            rand_id = random.randint(low, high)

            if (rand_id != id) and (rand_id not in list(self.__id_dict.values())):
                return rand_id

            count += 1
            if count > 100:
                print(f"ID dictionary is getting full, ID = {id}.")
                sys.exit(2)

    def mapId(self, id, length):
        if id in self.__id_dict:
            return self.__id_dict[id]
        else:
            self.__id_dict[id] = self._getRandomId(id, length)
            return self.__id_dict[id]

# Remove the payload
def payload_stripping(pkt):

    # Find the last recognized layer and remove its payload
    for n in range (len(pkt.layers()), 0, -1):
        current_layer = pkt[n - 1]
        if any(header in current_layer for header in PAYLOAD_LAYERS_LIST):
            current_layer.remove_payload()
            #print (f"Packet #{pkt_no}: removed the payload.")
            break
    return pkt

# VxLAN Stripping
def vxlan_stripping(pkt):

    if VXLAN in pkt:
        pkt = pkt.getlayer(Ether, 2)

        # Pad the packet to 64 if necessary
        pkt_len = len(pkt)
        if pkt_len < 60:
            pkt = pkt / Padding('\x00' * (60 - pkt_len))

        #print (f"Packet #{pkt_no}: removed the VxLAN header.")
        return pkt

# MPLS L3 VPN Stripping
def mpls_stripping(pkt):

    if MPLS in pkt:
        # Find the first MPLS label and save the layer below it
        layer = pkt.getlayer(MPLS)
        mpls_lower_layer = layer.underlayer

        # Find the last MPLS label
        while type(layer) is MPLS:
            layer = layer.payload

        # Update the EtherType in layer under all the MPLS labels
        if type(layer) is IP or type(layer) is IPv6:
            version = layer.version
            mpls_lower_layer.remove_payload()
            mpls_lower_layer.add_payload(layer)
            if type(layer) is IP:
                mpls_lower_layer.type = 0x0800
            if type(layer) is IPv6:
                mpls_lower_layer.type = 0x86DD

            # Pad the packet to 64 if necessary
            pkt_len = len(pkt)
            if pkt_len < 60:
                pkt = pkt / Padding('\x00' * (60 - pkt_len))

            #print (f"Packet #{pkt_no}: removed the MPLS labels.")
            return pkt

def reassemble_pkt(pkt):

    # Find the first IPv4 or IPv6 header
    for n in range (0, len(pkt.layers())):
        layer = pkt.getlayer(n)

        # IPv4
        if type(layer) is IP:

            # Process fragmented IPv4 packet
            if layer.flags == "MF" or layer.frag > 0:

                # Get the fields related to the fragmentation
                timestamp = pkt.time
                offset = layer.frag * 8
                length = layer.len - layer.ihl * 4
                payload = bytes(layer.payload)
                mf = layer.flags == "MF"

                # Save the fragment to the fragment dictionary
                if layer.id in frag_list:
                    frag_list[layer.id].add_fragment(timestamp=timestamp, first=offset, last=offset+length-1, payload=payload, mf=mf)
                else:
                    frag_list[layer.id] = FragPkt(timestamp=timestamp, first=offset, last=offset+length-1, payload=payload, mf=mf)

                # If all fragments have been received, save the complete reassembled packet
                if frag_list[layer.id].fragment_completed():

                    # Replace the payload of the last fragment with the reassembled payload
                    layer.remove_payload()
                    layer.add_payload(frag_list[layer.id].get_payload())

                    # Update the IPv4 header fields: Total Length, Flags, Fragment Offset, and Header Checksum
                    del layer.len
                    del layer.flags
                    del layer.frag
                    del layer.chksum
                    pkt = Ether(pkt.build())
                    pkt.time = timestamp

                    # Remove the fragments from the fragment dictionary
                    del frag_list[layer.id]

                    # Return the reassembled IPv4 packet
                    return pkt
                else:
                    return None

            # If the packet is not fragmented there's nothing to do
            else:
                return pkt

        # IPv6
        elif type(layer) is IPv6:

            # Get the fields related to the fragmentation
            ipv6_layer = layer
            length = layer.plen
            frag_layer = None
            i = n + 1
            layer = pkt.getlayer(i)
            while type(layer) in IPV6_EXT_HDRS:
                if type(layer) is IPv6ExtHdrFragment:
                    frag_layer = layer
                    timestamp = pkt.time
                    offset = layer.offset * 8
                    length -= 8
                else:
                    length -= layer.len * 8
                last_layer = layer
                i += 1
                layer = pkt.getlayer(i)

            # Process fragmented IPv6 packet
            if frag_layer:
                payload = bytes(last_layer.payload)

                # Save the fragment to the fragment dictionary
                if frag_layer.id in frag_list:
                    frag_list[frag_layer.id].add_fragment(timestamp=timestamp, first=offset, last=offset+length-1, payload=payload, mf=frag_layer.m)
                else:
                    frag_list[frag_layer.id] = FragPkt(timestamp=timestamp, first=offset, last=offset+length-1, payload=payload, mf=frag_layer.m)

                # If all fragments have been received, save the complete reassembled packet
                if frag_list[frag_layer.id].fragment_completed():

                    # Replace the payload of the last fragment with the reassembled payload
                    last_layer.remove_payload()
                    last_layer.add_payload(frag_list[frag_layer.id].get_payload())

                    # Remove the IPv6 Extension Header
                    frag_layer_upper = frag_layer.payload
                    frag_layer_lower = frag_layer.underlayer
                    frag_layer_lower.remove_payload()
                    frag_layer_lower.add_payload(frag_layer_upper)
                    frag_layer_lower.nh = frag_layer.nh

                    # Update the IPv6 header fields: Payload Length
                    del ipv6_layer.plen
                    pkt = Ether(pkt.build())
                    pkt.time = timestamp

                    # Remove the fragments from the fragment dictionary
                    del frag_list[frag_layer.id]

                    # Return the reassembled IPv6 packet
                    return pkt
                else:
                    return None

            # If the packet is not fragmented there's nothing to do
            else:
                return pkt

def anonymize_pkt (pkt):
    # Get and check the included FCS
    #pkt_has_fcs = False
    if Padding in pkt and len(pkt[Padding].load) >= FCS_LENGTH:
        padding = bytearray(pkt[Padding].load)
        (included_fcs,) = struct.unpack('<L', padding[-FCS_LENGTH:])
        computed_fcs = binascii.crc32(bytes(pkt)[:-FCS_LENGTH])
        #pkt_has_fcs = computed_fcs == included_fcs
        if computed_fcs == included_fcs:
            padding[:-FCS_LENGTH] = b'\x00\x00\x00\x00'
            pkt[Padding].load = padding

    # Fragmented packet - not 1st fragment
    if (((IP in pkt) and pkt[IP].frag) or
        ((IPv6ExtHdrFragment in pkt) and pkt[IPv6ExtHdrFragment].offset)):
        for n in range (len(pkt.layers()), 0, -1):
            current_layer = pkt[n - 1]
            if any(header in current_layer for header in PAYLOAD_LAYERS_LIST):
                current_layer.remove_payload()
                print (f"Packet #{pkt_no} Not first fragment, removing the payload.")
                break

    # GTP-C Version 1
    elif gtp.GTPHeader in pkt:
        msg_type = pkt[gtp.GTPHeader].gtp_type

        # Anonymize the IMSI
        if gtp.IE_IMSI in pkt[gtp.GTPHeader]:
            imsi = pkt[gtp.IE_IMSI].imsi
            imsi_length = len(imsi)
            mapped_imsi = f"{rand_imsi.mapId(int(imsi), imsi_length):0{imsi_length}d}".encode('ascii')
            pkt[gtp.IE_IMSI].imsi = mapped_imsi
            print (f"Packet #{pkt_no} GTPv{pkt[gtp.GTPHeader].version} Type={msg_type}, changing IMSI from {int(imsi)} to {int(mapped_imsi)}")
            #pkt.show()

        # Anonymize the MEI
        if gtp.IE_IMEI in pkt[gtp.GTPHeader]:
            mei = pkt[gtp.IE_IMEI].IMEI
            mei_length = len(mei)
            mapped_mei = f"{rand_imei.mapId(int(mei), mei_length):0{mei_length}d}".encode('ascii')
            pkt[gtp.IE_IMEI].IMEI = mapped_mei
            print (f"Packet #{pkt_no} GTPv{pkt[gtp.GTPHeader].version} Type={msg_type}, changing MEI from {int(mei)} to {int(mapped_mei)}")

        # Anonymize the MSISDN
        if gtp.IE_MSInternationalNumber in pkt[gtp.GTPHeader]:
            msisdn = pkt[gtp.IE_MSInternationalNumber].digits
            msisdn_length = len(msisdn)
            mapped_msisdn = f"{rand_msisdn.mapId(int(msisdn), msisdn_length):0{msisdn_length}d}".encode('ascii')
            pkt[gtp.IE_MSInternationalNumber].digits = mapped_msisdn
            print (f"Packet #{pkt_no} GTPv{pkt[gtp.GTPHeader].version} Type={msg_type}, changing MSISDN from {int(msisdn)} to {int(mapped_msisdn)}")

    # GTP-C Version 2
    elif GTPHeader in pkt:
        msg_type = pkt[GTPHeader].gtp_type

        # Anonymize the IMSI
        if IE_IMSI in pkt[GTPHeader]:
            imsi = pkt[IE_IMSI].IMSI
            imsi_length = len(imsi)
            mapped_imsi = f"{rand_imsi.mapId(int(imsi), imsi_length):0{imsi_length}d}".encode('ascii')
            pkt[IE_IMSI].IMSI = mapped_imsi
            print (f"Packet #{pkt_no} GTPv{pkt[GTPHeader].version} Type={msg_type}, changing IMSI from {int(imsi)} to {int(mapped_imsi)}")

        # Anonymize the MEI
        if IE_MEI in pkt[GTPHeader]:
            mei = pkt[IE_MEI].MEI
            mei_length = len(mei)
            mapped_mei = f"{rand_imei.mapId(int(mei), mei_length):0{mei_length}d}".encode('ascii')
            pkt[IE_MEI].MEI = mapped_mei
            print (f"Packet #{pkt_no} GTPv{pkt[GTPHeader].version} Type={msg_type}, changing MEI from {int(mei)} to {int(mapped_mei)}")

        # Anonymize the MSISDN
        if IE_MSISDN in pkt[GTPHeader]:
            msisdn = pkt[IE_MSISDN].digits
            msisdn_length = len(msisdn)
            mapped_msisdn = f"{rand_msisdn.mapId(int(msisdn), msisdn_length):0{msisdn_length}d}".encode('ascii')
            pkt[IE_MSISDN].digits = mapped_msisdn
            print (f"Packet #{pkt_no} GTPv{pkt[GTPHeader].version} Type={msg_type}, changing MSISDN from {int(msisdn)} to {int(mapped_msisdn)}")

    # GTP-U Version 1
    elif gtp.GTP_U_Header in pkt:
        for n in range (len(pkt.layers()), 0, -1):
            current_layer = pkt[n - 1]
            if any(header in current_layer for header in PAYLOAD_LAYERS_LIST):
                #size = len(current_layer.payload)
                current_layer.remove_payload()
                #current_layer.add_payload(b'\x00' * size)
                #current_layer.add_payload(bytes(struct.unpack('B'*size, bytearray(i%256 for i in range(0, size)))))
                #print (f"Packet #{pkt_no} GTP-U, removing the payload.")
                break

    # PFCP
    elif PFCP in pkt:
        ie_list = []
        if PFCPSessionEstablishmentRequest in pkt[PFCP].payload:
            ie_list = pkt[PFCP][PFCPSessionEstablishmentRequest].IE_list
        elif PFCPSessionModificationRequest in pkt[PFCP].payload:
            ie_list = pkt[PFCP][PFCPSessionModificationRequest].IE_list
        for ie in ie_list:
            if (ie.ietype == AFFIRMED_PFCP_SESSION_ESTABLISHMENT_REQUEST or
                ie.ietype == AFFIRMED_PFCP_SESSION_MODIFICATION_REQUEST):
                data = bytearray(ie.data)
                index = data.find(AFFIRMED_MAGIC_STRING)
                while index > 0 and index < len(data):
                    index += len(AFFIRMED_MAGIC_STRING)
                    (msg_type, msg_len) = struct.unpack_from('!HH', data, index)
                    index += struct.calcsize('!HH')
                    if msg_type == AFFIRMED_MSG_TYPE_WfSessionMcdTableFullSchema:
                        msg = FpGwMsg_pb2.WfSessionMcdTableFullSchema()
                        try:
                            msg.ParseFromString(data[index:index + msg_len])
                        except:
                            pass

                        # Anonymize the IMSI
                        if msg.HasField('imsi'):
                            imsi_length = len(str(msg.imsi))
                            mapped_imsi = rand_imsi.mapId(msg.imsi, imsi_length)
                            print (f"Packet #{pkt_no} PFCP, changing IMSI from {msg.imsi} to {mapped_imsi}")
                            msg.imsi = mapped_imsi

                        # Anonymize the MEI
                        if msg.HasField('imei'):
                            mei_length = len(str(msg.imei))
                            mapped_mei = rand_imei.mapId(msg.imei, mei_length)
                            print (f"Packet #{pkt_no} PFCP, changing MEI from {msg.imei} to {mapped_mei}")
                            msg.imei = mapped_mei

                        # Anonymize the MSISDN
                        if msg.HasField('msisdn'):
                            msisdn_length = len(str(msg.msisdn))
                            mapped_msisdn = rand_msisdn.mapId(msg.msisdn, msisdn_length)
                            print (f"Packet #{pkt_no} PFCP, changing MSISDN from {msg.msisdn} to {mapped_msisdn}")
                            msg.msisdn = mapped_msisdn

                        if msg.HasField('imsi') or msg.HasField('imei') or msg.HasField('msisdn'):
                            data[index:index + msg_len] = msg.SerializeToString()
                            ie.data = data

                        break

                    index = data.find(AFFIRMED_MAGIC_STRING, index + 1)

    # DIAMETER
    elif DiamG in pkt and False:
        layer_number = 1
        layer = pkt.getlayer('DiamG', layer_number)
        while layer:
            for avp in layer.avpList:

                # Anonymize the IMSI
                if ((avp.avpCode == DIAMETER_AVP_SUBSCRIPION_ID) and
                    (AVP_0_450 in avp and avp[AVP_0_450].val == DIAMETER_AVP_END_USER_IMSI) and
                    AVPNV_StrLenField in avp):
                    imsi = avp[AVPNV_StrLenField].val
                    imsi_length = len(imsi)
                    mapped_imsi = rand_imsi.mapId(int(imsi), imsi_length)
                    print (f"Packet #{pkt_no} DIAMETER, changing IMSI from {imsi} to {mapped_imsi}")
                    avp[AVPNV_StrLenField].remove_payload()
                    avp[AVPNV_StrLenField].val = f"{mapped_imsi:0{imsi_length}d}"

                # Anonymize the MEI
                elif ((avp.avpCode == DIAMETER_AVP_USER_EQUIPMENT_INFO_ID) and
                      (AVP_0_459 in avp and avp[AVP_0_459].val == DIAMETER_AVP_IMEISV) and
                    AVPNV_OctetString in avp):
                    mei = avp[AVPNV_OctetString].val.decode('ascii')
                    mei_length = len(mei)
                    mapped_mei = rand_imei.mapId(int(mei), mei_length)
                    print (f"Packet #{pkt_no} DIAMETER, changing MEI from {mei} to {mapped_mei}")
                    #avp[AVPNV_OctetString].remove_payload()
                    avp[AVPNV_OctetString].val = f"{mapped_mei:0{mei_length}d}".encode('ascii')

                # Anonymize the MSISDN
                elif ((avp.avpCode == DIAMETER_AVP_SUBSCRIPION_ID) and
                      (AVP_0_450 in avp and avp[AVP_0_450].val == DIAMETER_AVP_END_USER_E164) and
                    AVPNV_StrLenField in avp):
                    msisdn = avp[AVPNV_StrLenField].val
                    msisdn_length = len(msisdn)
                    mapped_msisdn = rand_msisdn.mapId(int(msisdn), msisdn_length)
                    print (f"Packet #{pkt_no} DIAMETER, changing MSISDN from {msisdn} to {mapped_msisdn}")
                    avp[AVPNV_StrLenField].remove_payload()
                    avp[AVPNV_StrLenField].val = f"{mapped_msisdn:0{msisdn_length}d}"

            layer_number += 1
            layer = pkt.getlayer('DiamG', layer_number)
                
    # Update the FCS
    #if pkt_has_fcs:
    #    computed_fcs = binascii.crc32(bytes(pkt)[:-FCS_LENGTH])
    #    padding[:-FCS_LENGTH] = struct.pack('<L', computed_fcs)
    #    pkt[Padding].load = padding

    return pkt

# Main program
def main():

    # Script requires Scapy v2.4.4
    if scapy.__version__ != "2.4.4":
        print("This script requires Scapy v2.4.4")
        #sys.exit(2)

    argv = sys.argv[1:]
    in_file = ''
    out_file = ''

    try:
        opts, args = getopt.getopt(argv, "i:o:", ["input_file=, output_file="])
    except getopt.GetoptError:
        print (CMD_SYNTAX)
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-i", "--input_file"):
            in_file = arg
        elif opt in ("-o", "--output_file"):
            out_file = arg

    if in_file == '':
        print (CMD_SYNTAX)
        sys.exit(2)

    if out_file == '':
        print (CMD_SYNTAX)
        sys.exit(2)

    # DIAMETER headers can be piggybacked
    bind_layers(DiamG, DiamG)

    # Do some needed updates to the gto and gtp_v2 contributions
    gtp_contrib_ext.gtp_contrib_mod()
    
    frag_list = {}

    rand_imsi = PcapRandId(6)
    rand_imei = PcapRandId(6)
    rand_msisdn = PcapRandId(4)

    in_pcap = PcapReader(in_file)
    out_hdrs_pcap = PcapWriter(out_file + "_hrds")
    out_clean_pcap = PcapWriter(out_file + "_clean")

    for pkt_no, pkt in enumerate(in_pcap, start = 1):

        # Save the headers of the packet (no payload)
        headers = pkt
        headers = payload_stripping(headers)
        out_hdrs_pcap.write(headers)

        # Remove the VXLAN header
        pkt = vxlan_stripping(pkt)

        # Remove the MPLS labels
        pkt = mpls_stripping(pkt)

        # Only reassemble PFCP packets
        pkt = reassemble_pkt(pkt)
        if pkt:
            # Anonymize the packet
            pkt = anonymize_pkt(pkt)

            # Write the packet
            out_clean_pcap.write(pkt)

if __name__ == "__main__":
    main()
