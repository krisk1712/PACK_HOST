import os
import socket
import struct
from ctypes import *
import threading
import time
from netaddr import IPNetwork, IPAddress


host= "10.0.2.15"

subnet = "10.0.2.0/24"


class IP(Structure):
    _fields_ =  [
        ("ihl",     c_ubyte, 4),
        ("version", c_ubyte, 4),
        ("tos",     c_ubyte),
        ("len",     c_ushort),
        ("id",      c_ushort),
        ("offset",  c_ushort),
        ("ttl",     c_ubyte),
        ("protocol_num", c_ubyte),
        ("sum",         c_ushort),
        ("src",         c_ulong),
        ("dst",         c_ulong)
    ]


    def __new__(self, socket_buffer=None):
        return  self.from_buffer_copy(socket_buffer)
    def __init__(self, socket_buffer=None):

        # map protocol constant to their names
        self.protocol_map = {1:"ICMP",6:"TCP",17:"UDP"}

        #human readable ip addre
        self.src_address = socket.inet_ntoa(struct.pack("<L",self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L",self.dst))

        #human proto

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)



if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL, 1)

if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL , socket_protocol.RCVALL_ON)


try:

    while True:

        raw_buffer = sniffer.recvfrom(65565)[0]

        ip_header = IP(raw_buffer[0:32])

        print "Protocol: %s %s --> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
except KeyboardInterrupt:
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)


class ICMP(Structure):
    __fields__ = [
        ("type",  c_ubyte),
        ("type",  c_ubyte),
        ("type",  c_ushort),
        ("type",  c_ushort),
        ("type",  c_ushort)
    ]



    def __new__(self, socket_buffer):
        return self.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer):
        pass
        # map protocol constant to their names
        self.protocol_map = {1: "ICMP", 6: "TCP", 17: "UDP"}

        # human readable ip addre
        self.src_address = socket.inet_ntoa(struct.pack("<L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("<L", self.dst))

        # human proto

        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except:
            self.protocol = str(self.protocol_num)

if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL, socket_protocol.RCVALL_ON)

try:
    while True:
        raw_buffer = sniffer.recvfrom(65565)[0]
        ip_header = IP(raw_buffer[0:32])
        print "Protocol : %s %s --> %s " % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)

except KeyboardInterrupt:
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)




    if ip_header.protocol == "ICMP":

        offset = ip_header.ihl * 4
        buf = raw_buffer[offset:offset + sizeof(ICMP)]

        icmp_header = ICMP(buf)

        print "ICMP -> Type: %d Code : %d " % (icmp_header.type, icmp_header.code)





if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL, 1)

if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL , socket_protocol.RCVALL_ON)


try:

    while True:

        raw_buffer = sniffer.recvfrom(65565)[0]

        ip_header = IP(raw_buffer[0:32])

        print "Protocol: %s %s --> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
except KeyboardInterrupt:
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

magic_message = "PYTHONRULES!"



def udp_sender(subnet, magic_message):
    time.sleep(5)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    for ip in IPNetwork(subnet):
        try:
            sender.sendto(magic_message, ("%s" % ip,65212))
        except:
            pass





if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL, 1)

if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL , socket_protocol.RCVALL_ON)


try:

    while True:

        raw_buffer = sniffer.recvfrom(65565)[0]

        ip_header = IP(raw_buffer[0:32])

        print "Protocol: %s %s --> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
except KeyboardInterrupt:
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)






thr = threading.Thread(target=udp_sender, args=(subnet, magic_message))
thr.start()



if os.name == "nt":
    socket_protocol = socket.IPPROTO_IP
else:
    socket_protocol = socket.IPPROTO_ICMP

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
sniffer.bind((host, 0))
sniffer.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL, 1)

if os.name == "nt":
    sniffer.ioctl(socket.SIO_RCVALL , socket_protocol.RCVALL_ON)


try:

    while True:

        raw_buffer = sniffer.recvfrom(65565)[0]

        ip_header = IP(raw_buffer[0:32])

        print "Protocol: %s %s --> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
except KeyboardInterrupt:
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)






try:
    while True:
        if os.name == "nt":
            socket_protocol = socket.IPPROTO_IP
        else:
            socket_protocol = socket.IPPROTO_ICMP

        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocol)
        sniffer.bind((host, 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        if os.name == "nt":
            sniffer.ioctl(socket.SIO_RCVALL, socket_protocol.RCVALL_ON)

        try:

            while True:
                raw_buffer = sniffer.recvfrom(65565)[0]

                ip_header = IP(raw_buffer[0:32])

                print "Protocol: %s %s --> %s" % (ip_header.protocol, ip_header.src_address, ip_header.dst_address)
        except KeyboardInterrupt:
            if os.name == "nt":
                sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

        if icmp_header.code == 3 and icmp_header.type == 3:
            if IPAddress(ip_header.src_address) in IPNetwork(subnet):
                if raw_buffer[len(raw_buffer)-len(magic_message):] == magic_message:
                    print "Host UP are : %s" % (ip_header.src_address)
except KeyboardInterrupt:
    if os.name == "nt":
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)