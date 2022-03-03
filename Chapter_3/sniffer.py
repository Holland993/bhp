import socket
import os

HOST = '127.0.0.1'

def main():
    # create raw socket, bin to public interface
    if os.name == 'nt':
        socket_protocal = socket.IPPROTO_IP
    else:
        socket_protocal = socket.IPPROTO_ICMP

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket_protocal)
    sniffer.bind((HOST, 0))
    # include the IP Header in the capture
    sniffer.setsockopt(socket.SIO_RCVALL, socket.RCVALL_ON)

    # read one packet
    print(sniffer.recv(65565))

    # if we're on windows, turn off promiscuous mode
    if os.name == 'nt':
        sniffer.ioctl(socket.SIO_RCVALLm socket.RCVALL_OFF)

if __name__ == '__main__':
    main()
