#!/usr/bin/python -tt
# PROOF-OF-CONCEPT CODE
# Script to find the controlling PNIO frames
# 2017 Lockout
# Licensed under MIT license (MIT)
# Please see http://opensource.org/licekses/MIT for more details
# Depends on: Scapy

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import time
from scapy.all import *

MASTER = ""         # MASTER PLC MAC Addres
SLAVE = ""          # SLAVE PLC MAC Address
ETH = "eth0"
PCAPfile = ""       # PNIO PCAP file name
CTRL = ""           # Control frame candidate

packets = rdpcap(PCAPfile)


Dm = {} # Unique MASTER frames
Ds = {} # Unique SLAVE frames
Dg = [] # Master controlling frames

c = 0
pn = -1
for p in packets:
    pn += 1
    if p.haslayer(Ether) and p.haslayer(Raw):
        c += 1

        PNIO = p[Raw].load              # The whole PROFINET RT Frame payload
        FrameID = PNIO[0:2]             # PROFINET RT Frame ID. 0x8010 - Master, 0x8000 - Slave. Changes
        IOdata = PNIO[2:42]             # PROFINET IO Cycle Sevice data unit
        CycleID = PNIO[42:44]           # Cycle Counter. Changes
        DataStatus = PNIO[44:45]        # State, 1 - primary, 0 - backup
        TransferStatus = PNIO[45:46]    # Transfer status, 0 - OK

        if p[Ether].src== MASTER:
            Dm[IOdata] = pn
        if p[Ether].src == SLAVE:
            Ds[IOdata] = pn
        if p[Raw].load == CTRL:
            Dg.append(pn)

print("\nOverall Master -> Slave communication statistics:")
print(c, len(Dm), len(Ds))
print("\nMaster unique frames:")
print Dm
print("\nSlave unique frames:")
print Ds
print("\nControl frame occurances:")
print Dg
