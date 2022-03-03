from ctypes import *
import ipaddress
import socket
import struct
import sys
import os

class IP(Structure):
    _fields_ = [
        ("Version",     c_ubyte, 4),
        ("ihl",         c_ubyte, 4),
        ("tos", c_ubyte,  8),
        ("len", c_ushort, 16),
        ("id", c_ushort, 16),
        ("offset", c_ushort, 16),
        ("ttl", c_ubyte, 8),
        ("protocol_num", c_byte, 8),
        ("sum", c_ushort, 16),
        ("src", c_uint32, 32),
        ("dst", c_uint32, 32)
    ]
    def __new__(cls, socket_buffer=None):
        return cls.from_buffer_copy(socket_buffer)

    def __init__(self, socket_buffer=None):
        # human readable IP addresses
        self.src_address = socket.inet_ntoa(struct.pack("< L", self.src))
        self.dst_address = socket.inet_ntoa(struct.pack("< L", self.dst))

        # map protocal constants to their names
        self.protocol_map = {1: "ICMP", 6: "TCP",17: "UDP"}
        try:
            self.protocol = self.protocol_map[self.protocol_num]
        except Exception as e:
            print('%s No protocol for %s' % (e, self.protocol_num))

class ICMP:
    def __init__(self, buff):
        header = struct.unpack('<BBHHH', buff)
        self.type = header[0]
        self.code = header[1]
        self.sum = header[2]
        self.id = header[3]
        self.seq = header[4]

def sniff(host):
    # create raw socket, bin to public interface
    if os.name == 'nt':
        socket_protocal = socket.IPPROTO_IP
    else:
        socket_protocal = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocal)
    sniffer.bind((host, 0))
    # include the IP Header in the capture



    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # read one packet
    print(sniffer.recv(65565))

    # if we're on windows, turn off promiscuous mode
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            # read a packet
            raw_buffer = sniffer.recvfrom(65535)[0]
            # create an IP header from the first 20 bytes
            ip_header = IP(raw_buffer[0:20])
            # print the deteced protocol and hosts
            #print('protocol: %s %s -> %s' % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))

            #ip_header = IP(raw_buffer[0:20])

            if ip_header.protocol == "ICMP":
                print('Protocal: %s %s -> %s' % (ip_header.protocol, ip_header.src_address, ip_header.dst_address))
                print(f'Version: {ip_header.Version}')
                print(f'Header Length: {ip_header.ihl} TTL: {ip_header.ttl}')

                #Calculate where our ICMP packet starts
                offset = ip_header.ihl * 4
                buf = raw_buffer[offset:offset + 8]
                #create our ICMP structure
                icmp_header = ICMP(buf)
                print('ICMP -> Type: %s Code: %s\n' % (icmp_header.type, icmp_header.code))

    except KeyboardInterrupt:
        #if we're on Windows, turn off promiscuous mode
        if os.name == 'nt':
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        sys.exit()


if __name__ == '__main__':
    if len(sys.argv) == 2:
        host = sys.argv[1]
    else:
        host = '192.168.1.87'
    sniff(host)
