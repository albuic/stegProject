#!/usr/bin/python

import fcntl
import socket
import struct


def usage():
    print("options :                                                                 "
          "    '-h' or '--help'                                Show this help        "
          "    '-i <interface>' or '--interface <interface>'   Listen on <interface> "
          "                                                      Default : eth0      "
          "    '-p <port>' '--port <port>'                     Listen on <port>      "
          "                                                      Default : 80        ")
    iptable_help()

def iptable_help():
    print("**************************************************************************"
          "Please DO NOT FORGET to disable generating RST packets by kernel !        "
          "To do that run this command from the console:                             "
          "$ sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST --sport 8080 -j DROP "
          "**************************************************************************")

# Get IP address of specified interface
def get_interface_ip_address(interface_name):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', interface_name[:15])
    )[20:24])

