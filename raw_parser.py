from scapy.all import *
from struct import *

import re
import zlib
import geoip2.database
import os, subprocess
import optparse, zipfile, sys
import xml.etree.ElementTree as ET

data = './dl_test.pcap'
a = rdpcap(data)

sessions = a.sessions()

reader = geoip2.database.Reader('GeoLite2-City.mmdb')

g_pattern = "=IHHIIII"
g_pattern_size = struct.calcsize(g_pattern)

pcap_file = open(data, "rb")
gheader = pcap_file.read(g_pattern_size)

magic_num, v_major, v_minor, tz, flags, snaplen, network = struct.unpack(g_pattern, gheader)

print(magic_num, v_major, v_minor, tz, flags, snaplen, network)

for session in sessions:
    for packet in sessions[session]:
        try:
            if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                while(1):
                    (header, payload) = cap.next()
                    hdr = payload[:14]
                    packetdata = struct.unpack("!6s6sH", hdr)
                #ord(hdr[11])
                #    print()
                #print(struct.unpack("!6B", eth))
                #print(struct.unpack("!6B", eth[6:12]))
                #print(struct.unpack("!H", eth[12:14]))           
                
        except:
            pass

