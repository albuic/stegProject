#!/usr/bin/python3

import getopt
import sys
from netfilterqueue import NetfilterQueue
from scapy.all import *
import os
import time
import math


def usage():
    print("options :                                                                    \n"
          "    '-f <pcap_file>' or '--file=pcap_file'          Using pcap file as input \n"
          "    '-h' or '--help'                                Show this help           \n"
          "    '-i <interface>' or '--interface1=<interface>'  Listen on <interface>    \n"
          "                                                      Default : enp1s0       \n"
          "    '-j <interface>' or '--interface2=<interface>'  Listen on <interface>    \n"
          "                                                      Default : enp5s0       \n"
          "    '-p <port>' '--port=<port>'    TODO             Listen on <port>         \n"
          "                                                      Default : 80           \n"
          "    '-q <queue>' '--queue=<queue>'                  Use queue <queue>        \n"
          "                                                      Default : 0            \n")


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

def filter(packet):
    # Here is where the magic happens.
    millis = int(round(time.time() * 1000))
    filter_with_time(packet, millis)

queue = []
def filter_with_time(packet, time):
    global queue
    queue.append([time])

    if len(queue) > 9:
        queue.pop(0)
    if len(queue) > 1:


        means = 0
        # Interval with previous packet in 1 and means
        for i in range(1, len(queue)):
            if((len(queue)-1) == i):
                queue[i].append(queue[i][0] - queue[i-1][0])
            else:
                queue[i][1] = queue[i][0] - queue[i-1][0]
            means += queue[i][1]
        means = means / (len(queue)-1)

        square_sum = 0
        for i in range(1, len(queue)):
            if((len(queue)-1) == i):
                # Difference from means
                queue[i].append(means - queue[i][1])
                # Square of previous
                queue[i].append(queue[i][2]*queue[i][2])
            else:
                # Difference from means
                queue[i][2] = means - queue[i][1]
                # Square of previous
                queue[i][3] = queue[i][2]*queue[i][2]
            square_sum += queue[i][3]
        # Standard deviation
        queue[len(queue)-1].append( math.sqrt( abs(square_sum) / (len(queue)-1) ) )
    data = ""
    if use_file:
        data = packet.load
    else:
        data = packet.get_payload()
    pkt = IP(data)
    if len(queue) > 1:
        info = "packet : [src.ip: " + str(pkt.src) + ", dst.ip: " + str(pkt.dst) + " ]" + " ssd= " + str(queue[len(queue)-1][4])
    else:
        info = "packet : [src.ip: " + str(pkt.src) + ", dst.ip: " + str(pkt.dst) + " ]"
    print(info)

    if not use_file:
        packet.accept()

use_file = False
def main(argv):
    interface1_name = 'enp1s0'
    interface2_name = 'enp5s0'
    listening_port = 80
    local_ip = 0
    iptables_queue = 0
    global use_file
    pcap_file_path = ""

    try:
        if argv[0] != "sudo":
            opts, args = getopt.getopt(argv[1:], "f:hi:j:p:q:", ["file", "help", "interface1=", "interface2=", "port=", "queue="])
        else:
            opts, args = getopt.getopt(argv[2:], "f:hi:j:p:q:", ["file", "help", "interface1=", "interface2=", "port=", "queue="])

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
