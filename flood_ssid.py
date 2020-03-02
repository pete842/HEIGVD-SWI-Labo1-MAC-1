#!/usr/bin/env python
# coding: utf-8

# Beacon send source : https://www.4armed.com/blog/forging-wifi-beacon-frames-using-scapy/

import sys
from scapy.all import *

list_ssid = []

if len(sys.argv) < 2:
    nbSSID = ord(input("Specify number of fake uuid to generate"))

    for i in range(nbSSID):
        list_ssid.append(uuid.uuid4());
else:
    f = open(sys.argv[1], 'r')
    list_ssid = f.readlines()

iface = "en0"
ap = "12:34:56:78:90:ab"
target = "ff:ff:ff:ff:ff:ff"

beacon = Dot11(type=0, subtype=8, addr1=target,addr2=ap, addr3=ap) / Dot11Beacon(cap='ESS+privacy') / Dot11Elt(ID='RSNinfo', info=(
    '\x01\x00'                 #RSN Version 1
    '\x00\x0f\xac\x02'         #Group Cipher Suite : 00-0f-ac TKIP
    '\x02\x00'                 #2 Pairwise Cipher Suites (next two lines)
    '\x00\x0f\xac\x04'         #AES Cipher
    '\x00\x0f\xac\x02'         #TKIP Cipher
    '\x01\x00'                 #1 Authentication Key Managment Suite (line below)
    '\x00\x0f\xac\x02'         #Pre-Shared Key
    '\x00\x00')                #RSN Capabilities (no extra capabilities)
)

for i in range(len(list_ssid)):
    essid = Dot11Elt(ID='SSID',info=list_ssid[i], len=len(list_ssid[i]))
    packets = RadioTap()/beacon/essid

    sendp(packets, iface=iface)
