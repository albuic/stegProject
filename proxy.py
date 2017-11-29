#!/usr/bin/python3

import getopt
import sys
from scapy.all import *
from statistics import *
from pathlib import Path
import os


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

queue = []
def filter(packet):
    global queue
    queue.append(packet)

    try:
        pkt = IP(packet.load)

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

    except Exception:
        queue.pop(len(queue)-1)
        print("packet dropped")
        return


window_number = 3
window_size = 10
def main(argv):
    interface_name = 'enp1s0'
    listening_port = 80
    local_ip = 0
    iptables_queue = 0
    pcap_file_path = ""
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
            print("Using " + str(window_number) + " windows")
        elif opt in ("-s", "--window-size"):
            window_size = int(arg)
            print("Using window with " + str(window_number) + " packets")

    # Setting iptables rules
    if pcap_file_path == "":
        sniff(store=0, prn=filter, iface=interface_name)
    else:
        sniff(store=0, prn=filter, offline=pcap_file_path)

if __name__ == "__main__":
    main(sys.argv)
