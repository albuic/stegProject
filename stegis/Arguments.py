import getopt
import traceback
import sys

from pathlib import Path


class Arguments:
    interface_name = "enp1s0"
    listening_port = 80
    pcap_file_path = ""
    window_size = 10
    window_number = 3


    def __init__(self, argv = None):
        if argv is None:
            self.get_arguments(sys.argv)
        else:
            self.get_arguments(argv)

    def get_arguments(self, argv):
        try:
            if argv[0] != "sudo":
                opts, args = getopt.getopt(argv[1:], "f:hi:n:p:s:", ["file=", "help", "interface=", "window-number=", "port=", "window-size="])
            else:
                opts, args = getopt.getopt(argv[2:], "f:hi:n:p:s:", ["file=", "help", "interface=", "window-number=", "port=", "window-size="])

        except getopt.GetoptError:
            Arguments.help()
            sys.exit(2)
        for opt, arg in opts:
            if opt in ("-h", "--help"):
                Arguments.help()
                sys.exit()
            elif opt in ("-f", "--file"):
                self.pcap_file_path = arg
                if not Path(self.pcap_file_path).is_file():
                    print("ERROR : File " + self.pcap_file_path + " does not exist.\n")
                    Arguments.help()
                    sys.exit(2)
                print("Using input file : " + self.pcap_file_path)
            elif opt in ("-i", "--interface"):
                self.interface_name = arg
                print("Using interface : " + self.interface_name)
            elif opt in ("-p", "--port"):
                # TODO : filter by port number
                self.listening_port = int(arg)
            elif opt in ("-n", "--window-number"):
                try:
                    self.window_number = int(arg)
                    if self.window_number < 2:
                        raise ValueError()
                except ValueError:
                    print("ERROR: Window number must be an integer > 1. (Set to '" + self.window_number + "')")
                    sys.exit(2)
                print("Using " + str(self.window_number) + " windows")
            elif opt in ("-s", "--window-size"):
                try:
                    self.window_size = int(arg)
                    if self.window_size < 2:
                        raise ValueError()
                except ValueError:
                    print("ERROR: Window size must be an integer > 1. (Set to '" + self.window_size + "')")
                    sys.exit(2)
                print("Using window with " + str(self.window_size) + " packets")

    def help():
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
