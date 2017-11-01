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
import time
import math


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
    # This flushes everything, be careful
    os.system("sudo iptables -F")
    os.system("sudo iptables -X")

queue = []
def filter(packet):
    global queue
    # Here is where the magic happens.
    millis = int(round(time.time() * 1000))
    queue.append([millis])
    if len(queue) > 10:
        queue.pop(0)
    if len(queue) > 1:
        means = 0
        # Interval with previous packet in 1 and means
        for i in range(1, len(queue)-1):
            queue[i].append(queue[i][0] - queue[i-1][0])
            means += queue[i][1]
        means = means / len(queue)

        square_sum = 0
        for i in range(1, len(queue)-1):
            # Difference from means
            queue[i].append(means - queue[i][1])
            # Square of previous
            queue[i].append(queue[i][2]*queue[i][2])
            square_sum += queue[i][3]
        # Standard deviation
        queue[len(queue)-1].append(math.root(square_sum / len(queue)-1))
    data = packet.get_payload()
    pkt = IP(data)
    if len(queue) > 1:
        info = "packet : [src.ip: " + str(pkt.src) + ", dst.ip: " + str(pkt.dst) + " ]" + " ssd= " + queue[len(queue)-1][4]
    else:
        info = "packet : [src.ip: " + str(pkt.src) + ", dst.ip: " + str(pkt.dst) + " ]"
    print(info)
    packet.accept()
    # if random.choice([True, False]):
    #     print(info + " Dropped")
    #     packet.drop()
    # else:
    #     print(info + " Forwarded")
    #     packet.accept()


def main(argv):
    interface1_name = 'enp1s0'
    interface2_name = 'enp5s0'
    listening_port = 80
    local_ip = 0
    iptables_queue = 0

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
            iptables_queue = arg

    # Setting iptables rules
    set_iptables_rules(interface1_name, interface2_name)

    nfqueue = NetfilterQueue()
    nfqueue.bind(iptables_queue, filter)
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        print('')
        nfqueue.unbind()
        # Removing iptables rules
        remove_iptables_rules()

if __name__ == "__main__":
    main(sys.argv)
