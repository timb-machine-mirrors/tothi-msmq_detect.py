#!/usr/bin/env python3
#
# detect whether the remote MSMQ service on 1801/tcp is enabled or not
# by sending a valid message to the target
#
# resources:
#  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqmq/b7cc2590-a617-45df-b6a3-1f31102b36fb
#  https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-mqqb/85498b96-f2c8-43b3-a108-c9d6269dc4af
#

from struct import pack
from datetime import datetime
from binascii import unhexlify
import uuid
import hexdump
import argparse
import socket

class bcolors:
    CYAN = '\033[96m'
    GREEN = '\033[32m'
    ENDC = '\033[0m'

parser = argparse.ArgumentParser(description="Query target whether the MSMQ service on 1801/tcp is enabled or not")

parser.add_argument('host', metavar='HOST', type=str, nargs=1, help='target host to query')
parser.add_argument('-d', action='store_true')
args = parser.parse_args()

HOST = args.host[0]
PORT = 1801

# BaseHeader
p =  b"\x10"  # VersionNumber (MUST be set to 0x10)
p += b"\x00"  # Reserved (arbitrary value)
p += b"\x00\x00"  # Flags (2-bytes) 0x0300
p += b"LIOR"  # Signature
p += pack("<I", 0x100)  # PacketSize
p += pack("<I", 4*24*60*60)  # TimeToReachQueue

# UserHeader
p += uuid.uuid4().bytes  # SourceQueueManager GUID
p += b"\x00"*16          # QueueManagerAddress GUID
p += b"\xff\xff\xff\xff" # TimeToBeRecevied
p += pack("<I", int(datetime.now().timestamp())) # SentTime
p += pack("<I", 0x1)     # MessageID

bits  = "00000" + "00" + "0" + "0" + "0"
bits += format(0x3, "03b") # DQ type (0x3 = private)
bits += format(0x4, "03b") # AQ type
bits += format(0x1, "03b") # RQ type
bits += "0"*13
p += unhexlify('{:0{}x}'.format(int(bits, 2), len(bits)//4)) # Flags

dq = "OS:{}\\private$\\queue\x00".format(HOST).encode("utf-16le") # DestinationQueue
p += pack("<H", len(dq)) + dq

p += b"\x00" * ((4 - len(p) % 4) % 4)  # padding

# MessagePropertiesHeader
messagebody = b'<?xml version="1.0"?>\r\n<string>Demo Message</string>'

p += b"\x00"          # Flags
p += b"\x00"          # LabelLength
p += pack("<H", 0x0)  # MessageClass
p += b"\x00"*20       # CorrelationID
p += pack("<I", 0x0)  # BodyType
p += pack("<I", 0x0)  # ApplicationTag
p += pack("<I", len(messagebody)) # MessageSize
p += pack("<I", len(messagebody)) # AllocationBodySize
p += pack("<I", 0x0)      # PrivacyLevel (NO ENCRYPTION)
p += pack("<I", 0x800e)   # HashAlgorithm (SHA512)
p += pack("<I", 0x6801)   # EncryptionAlgorithm (RC4)
p += pack("<I", 0x0)      # ExtensionSize
p += messagebody + b"\x00" # MessageBody

# fix size
p = bytearray(p)
p[8:12] = pack("<I", len(p))
p = bytes(p)

if args.d:
    print(bcolors.CYAN + "[*] SENDING:")
    hexdump.hexdump(p)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((HOST, PORT))
s.sendall(p)
resp = s.recv(512)
s.close()

if args.d:
    print()
    print("[*] RESPONSE:")
    hexdump.hexdump(resp)
    print(bcolors.ENDC)

if len(resp) == 0:
    print("[-] No response received from {}:1801".format(HOST))
elif resp[4:8] == b"LIOR":
    print(bcolors.GREEN + "[+] Signature has been found in response: MSMQ on {}:1801 seems to be running".format(HOST) + bcolors.ENDC)
else:
    print("[?] Response received from {}:1801 but signature is invalid".format(HOST))
