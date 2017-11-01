import getopt
import sys

from util import *


def main(argv):
    interface_name = 'eth0'
    listening_port = 80
    local_ip = 0

    try:
        opts, args = getopt.getopt(argv, "hi:p:", ["help", "interface=", "port="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-i", "--interface"):
            interface_name = arg
            local_ip = get_interface_ip_address(interface_name)
        elif opt in ("-p", "--port"):
            listening_port = arg

if __name__ == '__main__':
    main()
