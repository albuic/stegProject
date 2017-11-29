#!/usr/bin/python3

import getopt
import sys
from scapy.all import *
from statistics import *
from pathlib import Path
import os
import traceback
import time


def usage():
    print("options :                                                                                                                  \n"
          "    '-f <pcap file>' or '--file=<pcap file>'                         Using pcap file as input                              \n"
          "                                                                       Default : None                                      \n"
          "    '-h' or '--help'                                                 Show this help                                        \n"
          "    '-i <interface>' or '--interface=<interface>'                    Listen on <interface>                                 \n"
          "                                                                       Default : enp1s0                                    \n"
          "    '-n <number of windows>' or '--window-number=<number of windows' The <number of windows> to use for Regularity measure \n"
          "                                                                       Default : 3                                         \n"
          "    '-p <port>' '--port=<port>'    ***TODO***                        Listen on <port>                                      \n"
          "                                                                       Default : 80                                        \n"
          "    '-s <size of window>' or '--window-size=<size of window'         The <size of a window> to use for Regularity measure  \n"
          "                                                                       Default : 10                                        \n")



def sublists(l, n):
    """Yield successive n-sized lists from one list."""
    for i in range(0, len(l), n):
        yield l[i:i + n]

packet_queue = []
timestamp_queue = []
def filter(packet):
    global packet_queue
    packet_queue.append(packet)
    if pcap_file_path == "":
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


window_number = 3
window_size = 10
pcap_file_path = ""
def main(argv):
    interface_name = 'enp1s0'
    listening_port = 80
    local_ip = 0
    iptables_queue = 0
    global pcap_file_path
    global window_size
    global window_number

    try:
        if argv[0] != "sudo":
            opts, args = getopt.getopt(argv[1:], "f:hi:n:p:s:", ["file=", "help", "interface=", "window-number=", "port=", "window-size="])
        else:
            opts, args = getopt.getopt(argv[2:], "f:hi:n:p:s:", ["file=", "help", "interface=", "window-number=", "port=", "window-size="])

    except getopt.GetoptError:
        usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-f", "--file"):
            pcap_file_path = arg
            if not Path(pcap_file_path).is_file():
                print("ERROR : File " + pcap_file_path + " does not exist.\n")
                usage()
                sys.exit(2)
            print("Using input file : " + pcap_file_path)
        elif opt in ("-i", "--interface"):
            interface_name = arg
            print("Using interface : " + interface_name)
        elif opt in ("-p", "--port"):
            # TODO : filter by port number
            listening_port = int(arg)
        elif opt in ("-n", "--window-number"):
            window_number = int(arg)
                if window_number < 2:
                    raise ValueError()
            except ValueError:
                print("ERROR: Window number must be an integer > 1. (Set to '" + window_number + "')")
                sys.exit(2)
            print("Using " + str(window_number) + " windows")
        elif opt in ("-s", "--window-size"):
            try:
                window_size = int(arg)
                if window_size < 2:
                    raise ValueError()
            except ValueError:
                print("ERROR: Window size must be an integer > 1. (Set to '" + window_size + "')")
                sys.exit(2)
            print("Using window with " + str(window_size) + " packets")

    if pcap_file_path == "":
        try:
            sniff(store=0, prn=filter, iface=interface_name)
        except OSError:
            print("ERROR: Interface '" + interface_name + "' does not exist are access denied (are you an admin ?)")
            sys.exit(2)
    else:
        sniff(store=0, prn=filter, offline=pcap_file_path)

if __name__ == "__main__":
    main(sys.argv)
