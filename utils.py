import getopt
import sys
import traceback

from pathlib import Path


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


def test_arguments(argv):
    global interface_name
    global listening_port
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
            try:
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

    return any
