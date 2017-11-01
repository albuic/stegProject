#!/usr/bin/python2

"""
    Use scapy to modify packets going through your machine.
    Based on NetfilterQueue to block packets in the kernel and pass them to scapy for validation
"""

import getopt
import sys
from netfilterqueue import NetfilterQueue
from scapy.all import *
import os

# All packets that should be filtered :

# If you want to use it as a reverse proxy for your machine
#iptablesr = "iptables -A OUTPUT -j NFQUEUE"

def usage():
    print("options :                                                                 "
          "    '-h' or '--help'                                Show this help        "
          "    '-i <interface>' or '--interface1=<interface>'  Listen on <interface> "
          "                                                      Default : enp1s0    "
          "    '-j <interface>' or '--interface2=<interface>'  Listen on <interface> "
          "                                                      Default : enp5s0    "
          "    '-p <port>' '--port=<port>'    TODO             Listen on <port>      "
          "                                                      Default : 80        "
          "    '-q <queue>' '--queue=<queue>'                  Use queue <queue>     "
          "                                                      Default : 0         ")


def set_iptables_rules(interface1, interface2):
    iptablesr1 = "sudo iptables -A FORWARD -j NFQUEUE -i " + interface1
    iptablesr2 = "sudo iptables -A FORWARD -j NFQUEUE -i " + interface2

    print("Adding iptable rules :")
    print(iptablesr1)
    print(iptablesr2)
    os.system(iptablesr1)
    os.system(iptablesr2)

def remove_iptables_rules():
    print("Flushing iptables.")
    # This flushes everything, you might wanna be careful
    os.system("sudo iptables -F")
    os.system("sudo iptables -X")

def filter(packet):
    # Here is where the magic happens.
    data = packet.get_payload()
    pkt = IP(data)
    info = "packet : [src.ip: " + str(pkt.src) + ", dst.ip: " + str(pkt.dst) + " ]"
    # if pkt.src == "192.168.1.2":
    if random.choice([True, False]):
        # Drop all packets coming from this IP
        print(info + " Dropped")
        packet.drop()
    else:
        # Let the rest go it's way
        print(info + " Forwarded")
        packet.accept()
    # If you want to modify the packet, copy and modify it with scapy then do :
    #packet.set_verdict_modified(nfqueue.NF_ACCEPT, str(packet), len(packet))


def main(argv):
    interface1_name = 'enp1s0'
    interface2_name = 'enp5s0'
    listening_port = 80
    local_ip = 0
    queue = 0

    try:
        opts, args = getopt.getopt(argv, "hi:j:p:q:", ["help", "interface1=", "interface2=", "port=", "queue="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-i", "--interface1"):
            interface1_name = arg
        elif opt in ("-j", "--interface2"):
            interface2_name = arg
        elif opt in ("-p", "--port"):
            # TODO : filter by port number
            listening_port = arg
        elif opt in ("-q", "--queue"):
            queue = arg

    # Setting iptables rules
    set_iptables_rules(interface1_name, interface2_name)
    # This is the intercept
    nfqueue = NetfilterQueue()
    nfqueue.bind(queue, filter)
    try:
        nfqueue.run() # Main loop
    except KeyboardInterrupt:
        print('')
        nfqueue.unbind()
        # Removing iptables rules
        remove_iptables_rules()

if __name__ == "__main__":
    main(sys.argv)
