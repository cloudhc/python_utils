import os
import socket
import struct
import sys

from socket import inet_ntoa

def to_hex(data):
    return ':'.join('%02x' % i for i in list(data))

def to_ipaddr(data):
    l = [(data>>24)&0xFF, (data>>16)&0xFF, (data>>8)&0xFF, data&0xFF]
    return ".".join('%d' % i for i in l)

def to_proto(data):
    return 'TCP' if data == 6 else 'UDP'

data = './dl_test.pcap'

pcap = open(data, 'rb')
pcap_sz = os.path.getsize(data)

gh_pattern = '=IHHIIII';
gh_pattern_size = struct.calcsize(gh_pattern)

magic_num, v_major, v_minor, tz, flags, snaplen, network = struct.unpack(gh_pattern, pcap.read(gh_pattern_size))

print("global header:", magic_num, v_major, v_minor, tz, flags, snaplen, network)

pcap_sz -= gh_pattern_size

count = 1

while pcap_sz > 0:
    print(" packet count:", count, "-------------------------------------------------------------")

    ph_pattern = "=IIII"
    ph_pattern_size = struct.calcsize(ph_pattern)

    ts_sec, ts_usec, incl_len, orig_len = struct.unpack(ph_pattern, pcap.read(ph_pattern_size))

    print("packet header:", ts_sec, ts_usec, incl_len, orig_len)

    pcap_sz -= (incl_len+16)

    eh_pattern = '!6B6BH'
    eh_pattern_size = struct.calcsize(eh_pattern)

    ether_data = struct.unpack(eh_pattern, pcap.read(eh_pattern_size))

    print(" ether header:", to_hex(ether_data[:6]), to_hex(ether_data[6:12]), to_hex(ether_data[12:]))

    if ether_data[12] == 0x8100:
        vh_pattern = '!BBBH'
        vh_pattern_size = struct.calcsize(vh_pattern)

        prio, id, vlan, type = struct.unpack(vh_pattern, pcap.read(vh_pattern_size))

        print("  vlan header:", prio, id, vlan, type)
        
    ih_pattern = '!BBHHBBBBHII'
    ih_pattern_size = struct.calcsize(ih_pattern)

    ip_data = struct.unpack(ih_pattern, pcap.read(ih_pattern_size))

    print("    ip header:", to_proto(ip_data[7]), to_ipaddr(ip_data[9]), to_ipaddr(ip_data[10]))

    if ip_data[7] == 6:
        th_pattern = '!HHIIBBHHHI'
        th_pattern_size = struct.calcsize(th_pattern)

        tcp_data = struct.unpack(th_pattern, pcap.read(th_pattern_size))

        print("   tcp header:", tcp_data[0], tcp_data[1], tcp_data[7])
        #print("   app header:", socket.getservbyport(tcp_data[1]))
        print("   app header:", tcp_data[1])

        pcap.read(incl_len - eh_pattern_size - ih_pattern_size - th_pattern_size)
    elif ip_data[7] ==  17:
        uh_pattern = '!HHHH'
        uh_pattern_size = struct.calcsize(uh_pattern)

        udp_data = struct.unpack(uh_pattern, pcap.read(uh_pattern_size))

        print("   udp header:", udp_data[0], udp_data[1], udp_data[2])
        #print("   app header:", socket.getservbyport(udp_data[1]))
        print("   app header:", udp_data[1])

        pcap.read(incl_len - eh_pattern_size - ih_pattern_size - uh_pattern_size)
    
    count += 1

print('End')
