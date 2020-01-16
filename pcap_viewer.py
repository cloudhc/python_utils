from scapy.all import *

import re
import zlib

data = './dl_test.pcap'
a = rdpcap(data)

sessions = a.sessions()

for session in sessions:
    for packet in sessions[session]:
        try:
            print(packet.show())
        except:
            pass

print("End")
