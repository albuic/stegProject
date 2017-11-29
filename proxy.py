#!/usr/bin/python3

import getopt
import sys
from netfilterqueue import NetfilterQueue
from scapy.all import *
from statistics import *
import os
import time
import math


def usage():
    print("options :                                                                                                                  \n"
          "    '-f <pcap file>' or '--file=<pcap file>'                         Using pcap file as input                              \n"
          "                                                                       Default : None                                      \n"
          "    '-h' or '--help'                                                 Show this help                                        \n"
          "    '-i <interface>' or '--interface1=<interface>'                   Listen on <interface>                                 \n"
          "                                                                       Default : enp1s0                                    \n"
          "    '-j <interface>' or '--interface2=<interface>'                   Listen on <interface>                                 \n"
          "                                                                       Default : enp5s0                                    \n"
          "    '-n <number of windows>' or '--window-number=<number of windows' The <number of windows> to use for Regularity measure \n"
          "                                                                       Default : 3                                         \n"
          "    '-p <port>' '--port=<port>'    ***TODO***                        Listen on <port>                                      \n"
          "                                                                       Default : 80                                        \n"
          "    '-q <queue>' '--queue=<queue>'                                   Use queue <queue>                                     \n"
          "                                                                       Default : 0                                         \n"
          "    '-s <size of window>' or '--window-size=<size of window'         The <size of a window> to use for Regularity measure  \n"
          "                                                                       Default : 10                                        \n")


def set_iptables_rules(iptables_queue, interface1, interface2):
    iptablesr1 = "sudo iptables -A FORWARD -j NFQUEUE --queue-num " + str(iptables_queue) + " -i " + interface1
    iptablesr2 = "sudo iptables -A FORWARD -j NFQUEUE --queue-num " + str(iptables_queue) + " -i " + interface2

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

def sublists(l, n):
    """Yield successive n-sized lists from one list."""
    for i in range(0, len(l), n):
        yield l[i:i + n]

def filter(packet):
    # Here is where the magic happens.
    millis = int(round(time.time() * 1000))
    filter_with_time(packet, millis)

queue = []
def filter_with_time(packet, time):
    global queue
    queue.append(packet)

    data = ""
    if use_file:
        try:
            data = packet.load
            packet.time
        except AttributeError:
            queue.pop(len(queue)-1)
            return
    else:
        data = packet.get_payload()
    pkt = IP(data)

    if len(queue) > ( window_size * window_number ):
        queue.pop(0)

    if len(queue) > ( (window_size * window_number) - 1 ):
        sub_queues = list(sublists(queue, window_size))
        sigmas = []
        for sq in sub_queues:
            sigmas.append(stdev( list(map(lambda p : p.time, sq)) ))
        pairwises = []
        for j in range(1, len(sigmas)):
            for i in range(0, j):
                pairwises.append(   abs(sigmas[j]-sigmas[i]) / sigmas[i]   )
        regularity = stdev(pairwises)

        info = "last packet : [src.ip: " + '%15s' % str(pkt.src) + ", dst.ip: " + '%15s' % str(pkt.dst) + " ]" + " ssd= " + str(regularity)
    else:
        info = "last packet : [src.ip: " + '%15s' % str(pkt.src) + ", dst.ip: " + '%15s' % str(pkt.dst) + " ]"
    print(info)

    if not use_file:
        packet.accept()

use_file = False
window_number = 3
window_size = 10
def main(argv):
    interface1_name = 'enp1s0'
    interface2_name = 'enp5s0'
    listening_port = 80
    local_ip = 0
    iptables_queue = 0
    global use_file
    pcap_file_path = ""
    global window_size
    global window_number

    try:
        if argv[0] != "sudo":
            opts, args = getopt.getopt(argv[1:], "f:hi:j:n:p:q:s:", ["file=", "help", "interface1=", "interface2=", "window-number=", "port=", "queue=", "window-size="])
        else:
            opts, args = getopt.getopt(argv[2:], "f:hi:j:n:p:q:s:", ["file=", "help", "interface1=", "interface2=", "window-number=", "port=", "queue=", "window-size="])

    except getopt.GetoptError:
        usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-f", "--file"):
            pcap_file_path = arg
            use_file = True
            print("Using input file : " + pcap_file_path)
        elif opt in ("-i", "--interface1"):
            interface1_name = arg
            print("Using interface : " + interface1_name)
        elif opt in ("-j", "--interface2"):
            interface2_name = arg
            print("Using interface : " + interface2_name)
        elif opt in ("-p", "--port"):
            # TODO : filter by port number
            listening_port = int(arg)
        elif opt in ("-q", "--queue"):
            iptables_queue = int(arg)
            print("Using queue : " + str(iptables_queue))
        elif opt in ("-n", "--window-number"):
            window_number = int(arg)
            print("Using " + str(window_number) + " windows")
        elif opt in ("-s", "--window-size"):
            window_size = int(arg)
            print("Using window with " + str(window_number) + " packets")

    # Setting iptables rules
    if not use_file:
        set_iptables_rules(iptables_queue, interface1_name, interface2_name)
        nfqueue = NetfilterQueue()
        nfqueue.bind(iptables_queue, filter)
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            print('')
            nfqueue.unbind()
            # Removing iptables rules
            remove_iptables_rules()
    else:
        pcapfile = rdpcap(pcap_file_path)
        for packet in pcapfile:
            time = int(round((packet.time * 1000)))
            filter_with_time(packet, time)

if __name__ == "__main__":
    main(sys.argv)
