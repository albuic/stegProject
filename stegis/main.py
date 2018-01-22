#!/usr/bin/python3

import sys
from scapy.all import *
from statistics import *
import os
import traceback
import time

from utils import *
from Arguments import *


packet_queue = []
timestamp_queue = []
def filter(packet):
    global packet_queue
    global timestamp_queue

    packet_queue.append(packet)
    if self.offline == "":
        timestamp_queue.append(int(round(time.time() * 1000)))
    else:
        timestamp_queue.append(int(round(packet.time * 1000)))

    try:
        if len(packet_queue) > ( window_size * window_number ):
            packet_queue.pop(0)
            timestamp_queue.pop(0)

        if len(packet_queue) > ( (window_size * window_number) - 1 ):
            sub_packet_queues = list(sublists(packet_queue, window_size))
            sub_timestamp_queues = list(sublists(timestamp_queue, window_size))
            sigmas = []
            for stq in sub_timestamp_queues:
                sigmas.append(stdev(stq))
            pairwises = []
            for j in range(1, len(sigmas)):
                for i in range(0, j):
                    pairwises.append(   abs(sigmas[j]-sigmas[i]) / sigmas[i]   )
            regularity = stdev(pairwises)

            info = "last packet : [src.ip: " + '%15s' % str(packet[IP].src) + ", dst.ip: " + '%15s' % str(packet[IP].dst) + " ]" + " ssd= " + str(regularity)
        else:
            info = "last packet : [src.ip: " + '%15s' % str(packet[IP].src) + ", dst.ip: " + '%15s' % str(packet[IP].dst) + " ]"
        print(info)

    except Exception:
        packet_queue.pop(len(packet_queue)-1)
        timestamp_queue.pop(len(timestamp_queue)-1)
        print("packet dropped :\n" + traceback.format_exc())
        packet
        return



if __name__ == "__main__":
    my_arguments = Arguments()

    if my_arguments.pcap_file_path == "":
        try:
            print("Using interface : " + my_arguments.interface_name)
            sniff(store=0, prn=filter, iface=my_arguments.interface_name)
        except OSError:
            print("ERROR: Interface '" + my_arguments.interface_name + "' does not exist or access is denied (are you an admin ?)")
            sys.exit(2)
    else:
        sniff(store=0, prn=filter, offline=pcap_file_path)
