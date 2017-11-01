#!/usr/bin/python2

"""
    Use scapy to modify packets going through your machine.
    Based on NetfilterQueue to block packets in the kernel and pass them to scapy for validation
"""

from netfilterqueue import NetfilterQueue
from scapy.all import *
import os

# All packets that should be filtered :

# If you want to use it as a reverse proxy for your machine
#iptablesr = "iptables -A OUTPUT -j NFQUEUE"

# If you want to use it for MITM :
iptablesr1 = "sudo iptables -A FORWARD -j NFQUEUE -i enp1s0"
iptablesr2 = "sudo iptables -A FORWARD -j NFQUEUE -i enp5s0"

print("Adding iptable rules :")
print(iptablesr1)
print(iptablesr2)
os.system(iptablesr1)
os.system(iptablesr2)

# If you want to use it for MITM attacks, set ip_forward=1 :
#print("Set ipv4 forward settings : ")
#os.system("sysctl net.ipv4.ip_forward=1")

drop_packet = True

def accept_one_on_two(packet):
    # Here is where the magic happens.
    data = packet.get_payload()
    pkt = IP(data)
    print("Got a packet ! source ip : " + str(pkt.src))
    # if pkt.src == "192.168.1.2":
    if drop_packet:
        # Drop all packets coming from this IP
        print("Dropped it. Oops")
        packet.accept()
        drop_packet = False
    else:
        # Let the rest go it's way
        print("Forwarding it.")
        packet.drop()
        drop_packet = True
    # If you want to modify the packet, copy and modify it with scapy then do :
    #packet.set_verdict_modified(nfqueue.NF_ACCEPT, str(packet), len(packet))


def main():
    # This is the intercept
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, accept_one_on_two)
    try:
        nfqueue.run() # Main loop
    except KeyboardInterrupt:
        print('')
        nfqueue.unbind()
        print("Flushing iptables.")
        # This flushes everything, you might wanna be careful
        os.system("sudo iptables -F")
        os.system("sudo iptables -X")


if __name__ == "__main__":
    main()
