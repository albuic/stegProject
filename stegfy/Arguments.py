import getopt
import traceback
import sys

from pathlib import Path


class Arguments:
    verbose = 0
    receiver = False
    sender = False
    input_file = None
    output_file = None
    input_string = None
    queue_number = 10
    time_shifter = False
    fields_shifter = False
    treshold = 50
    one_lower_limit = 70
    one_upper_limit = 100
    zero_lower_limit = 0
    zero_upper_limit = 30
    tcp_acknowledge_sequence_number_field = False
    tcp_initial_sequence_number_field = False
    ip_packet_identification_field = False
    ip_do_not_fragment_field = False
    ip_packet_identification_field_mask = '0000000000000001'


    def __init__(self, argv = None):
        if argv is None:
            self.get_arguments(sys.argv)
        else:
            self.get_arguments(argv)


    def get_arguments(self, argv):
        try:
            if argv[0] != "sudo":
                opts, args = getopt.getopt(argv[1:], "hi:o:q:rst:v:w:x:y:z:1234m:", ["help", "verbose=", "receiver", "sender", "input-file=", "output-file=", "queue-number=", "one-lower-limit=", "one-upper-limit=", "input-string=", "treshold=", "time-shifter", "fields-shifter", "zero-lower-limit=", "zero-upper-limit=", "tcp-acknowledge-sequence-number-field", "tcp-initial-sequence-number-field", "ip-packet-identification-field", "ip-do-not-fragment-field", "mask="])
            else:
                opts, args = getopt.getopt(argv[2:], "hi:o:q:rst:v:w:x:y:z:1234m:", ["help", "verbose=", "receiver", "sender", "input-file=", "output-file=", "queue-number=", "one-lower-limit=", "one-upper-limit=", "input-string=", "treshold=", "time-shifter", "fields-shifter", "zero-lower-limit=", "zero-upper-limit=", "tcp-acknowledge-sequence-number-field", "tcp-initial-sequence-number-field", "ip-packet-identification-field", "ip-do-not-fragment-field", "mask="])
        except getopt.GetoptError as err:
            print(err)
            Arguments.help()
            sys.exit(2)

        for opt, arg in opts:
            if opt in ("-h", "--help"):
                Arguments.help()
                sys.exit()
            elif opt in ("-v", "--verbose"):
                try:
                    self.verbose = int(arg)
                except ValueError:
                    print("ERROR : Verbose level '" + arg + "' is not an integer.")
                    sys.exit(2)
            elif opt in ("-i", "--input-file"):
                self.input_file = arg
                if not Path(self.input_file).is_file():
                    print("ERROR : Input file " + arg + " does not exist.")
                    sys.exit(2)
                self.sender = True
            elif opt in ("-o", "--output-file"):
                self.output_file = arg
                self.receiver = True
            elif opt in ("-r", "--receiver"):
                self.receiver = True
            elif opt in ("-s", "--sender"):
                self.sender = True
            elif opt in ("--input-string"):
                self.input_string = arg
                self.sender = True
            elif opt in ("-q", "--queue-number"):
                try:
                    self.queue_number = int(arg)
                except ValueError:
                    print("ERROR : Queue number '" + arg + "' is not an integer.")
                    sys.exit(2)
            elif opt in ("-y", "--one-lower-limit"):
                try:
                    self.one_lower_limit = int(arg)
                except ValueError:
                    print("ERROR : One lower limit '" + arg + "' is not an integer.")
                    sys.exit(2)
                self.time_shifter = True
            elif opt in ("-z", "--one-upper-limit"):
                try:
                    self.one_upper_limit = int(arg)
                except ValueError:
                    print("ERROR : One upper limit '" + arg + "' is not an integer.")
                    sys.exit(2)
                self.time_shifter = True
            elif opt in ("-w", "--zero-lower-limit"):
                try:
                    self.zero_lower_limit = int(arg)
                except ValueError:
                    print("ERROR : Zero lower limit '" + arg + "' is not an integer.")
                    sys.exit(2)
                self.time_shifter = True
            elif opt in ("-x", "--zero-upper-limit"):
                try:
                    self.zero_upper_limit = int(arg)
                except ValueError:
                    print("ERROR : Zero upper limit '" + arg + "' is not an integer.")
                    sys.exit(2)
                self.time_shifter = True
            elif opt in ("-t", "--treshold"):
                try:
                    self.treshold = int(arg)
                except ValueError:
                    print("ERROR : Treshold '" + arg + "' is not an integer.")
                    sys.exit(2)
                self.time_shifter = True
            elif opt in ("-1", "--tcp-acknowledge-sequence-number-field"):
                self.tcp_acknowledge_sequence_number_field = True
                self.fields_shifter = True
            elif opt in ("-2", "--tcp-initial-sequence-number-field"):
                self.tcp_initial_sequence_number_field = True
                self.fields_shifter = True
            elif opt in ("-3", "--ip-packet-identification-field"):
                self.ip_packet_identification_field = True
                self.fields_shifter = True
            elif opt in ("-4", "--ip-do-not-fragment-field"):
                self.ip_do_not_fragment_field = True
                self.fields_shifter = True
            elif opt in ("--time-shifter"):
                self.time_shifter = True
            elif opt in ("--fields-shifter"):
                self.fields_shifter = True
            elif opt in ("-m", "--mask"):
                if len(arg) != 16:
                    print("ERROR : Mask '" + arg + "' is not a 16 character string representing a mask.")
                    sys.exit(2)
                for my_char in arg:
                    if my_char != '0' and my_char != '1':
                        print("ERROR : Mask '" + arg + "' contained unkown character.")
                        sys.exit(2)
                self.ip_packet_identification_field_mask = arg


    def test_and_show_configuration(self):
        # Testing sender or receiver mode only and print result
        if self.sender and self.receiver:
            print("ERROR : Cannot use both sender and receiver mode at the same time.")
            sys.exit(2)
        elif self.sender:
            print("Using sender mode.")
        elif self.receiver:
            print("Using receiver mode.")
        else:
            print("Receiver or Sender mode not set.")
            self.receiver = True
            print("Using receiver mode as default mode.")

        print("Using queue : '" + str(self.queue_number) + "'.")

        # Testing file and input string
        if self.sender:
            if self.input_file != None:
                print("Using input file : '" + self.input_file + "'.")
            elif self.input_string != None:
                if len(self.input_string) > 0:
                    print("Using input string :\n\n" + self.input_string + "\n")
                else:
                    print("ERROR : Input string is empty.")
            else:
                print("ERROR : Input file or input string not set.")
                sys.exit(2)
        else:
            if self.output_file != None:
                print("Using output file : " + self.output_file + "'.")
            else:
                print("Not using output files.")

        # Testing Time Shifter or Fields Shifter
        if not self.time_shifter and not self.fields_shifter:
            print("Time Shifter or Fields Shifter mode not set.")
            self.time_shifter = True
            print("Using Time Shifter as a default mode.")

        # Testing lower/upper limits and treshold (Time Shifter setup)
        if self.time_shifter:
            if self.zero_lower_limit > self.zero_upper_limit:
                print("ERROR : The zero lower limit ('" + str(self.zero_lower_limit) + "') is greater than the zero upper limit ('" + str(self.zero_upper_limit) + "').")
                sys.exit(2)
            if self.one_lower_limit > self.one_upper_limit:
                print("ERROR : The one lower limit ('" + str(self.one_lower_limit) + "') is greater than the one upper limit ('" + str(self.one_upper_limit) + "').")
                sys.exit(2)
            print("The treshold is " + str(self.treshold) + ".\n"
                  "The one lower limit is " + str(self.one_lower_limit) + ".\n"
                  "The one upper limit is " + str(self.one_upper_limit) + ".\n"
                  "The zero lower limit is " + str(self.zero_lower_limit) + ".\n"
                  "The zero upper limit is " + str(self.zero_upper_limit) + ".\n")
            if self.one_lower_limit < self.treshold:
                print("WARNING : The one lower limit ('" + str(self.one_lower_limit) + "') is lower than the treshold ('" + str(self.treshold) + "').")
            if self.zero_upper_limit > self.treshold:
                print("WARNING : The zero upper limit ('" + str(self.zero_upper_limit) + "') is greater than the treshold ('" + str(self.treshold) + "').")
            if self.zero_lower_limit == self.zero_upper_limit:
                print("INFO : The zero lower limit equals the zero upper limit ('" + str(self.zero_upper_limit) + "').")
            if self.one_lower_limit == self.one_upper_limit:
                print("INFO : The one lower limit equals the one upper limit ('" + str(self.one_upper_limit) + "').")


        # Testing Fields Shifter setup
        if self.fields_shifter and not self.tcp_initial_sequence_number_field \
                               and not self.tcp_acknowledge_sequence_number_field \
                               and not self.ip_do_not_fragment_field \
                               and not self.ip_packet_identification_field:
            print("Fields Shifter is set but no fields are set to be used.")
            self.ip_do_not_fragment_field = True
            print("Using the IP Do Not Fragment Field as a default.")

        print("\n\n")

    @staticmethod
    def help():
        print("Usage:                                                                                                              \n"
              "    './stegfy.py [options] [string to send]'                                                                        \n"
              "                                                                                                                    \n"
              "                                                                                                                    \n"
              "Manual:                                                                                                             \n"
              "This software will hide data in the network. It can hide data in delays between packets or in some tcp/ip fields.   \n"
              "You must specify either '--receiver' or '--sender' to use this program (You cannot use both at the same time).      \n"
              "Using some options will activate '--time-shifter' or '--fields-shifter' even if you do not use those directly.      \n"
              "By default, the program start in Time Shifter Receiver mode.                                                        \n"
              "                                                                                                                    \n"
              "                                                                                                                    \n"
              "Options :                                                                                                           \n"
              "    '-h' or '--help'                                      Show this help and exit                                   \n"
              "    '-v' or '--verbose'                                   Set verbose level (Show debug info) from 1 to 5           \n"
              "                                                            Default : 0                                             \n"
              "    '-r' or '--receiver'                                  Start program in receiver mode                            \n"
              "                                                            Default : Receiver mode                                 \n"
              "    '-s' or '--sender'                                    Start program in sender mode                              \n"
              "                                                            Default : Receiver mode                                 \n"
              "    '-i <text file>' or '--input-file=<text file>'        Using text file as input                                  \n"
              "                                                            Default : None                                          \n"
              "    '-o <text file>' or '--output-file=<text file>'       Using text file as output (program will replace it)       \n"
              "                                                            Default : None                                          \n"
              "    '-q <integer>' or '--queue-number=<integer>'          The queue number used (netfilter queue)                   \n"
              "                                                            Default : 10                                            \n"
              "    '--time-shifter'                                      Activate time shifting with default parameters            \n"
              "                                                            Default : Activated if '--fields-shifter' is not set    \n"
              "    '-t <integer>' or '--treshold=<integer>'              The treshold in milliseconds (see graph below)            \n"
              "                                                            Default : 50                                            \n"
              "    '-w <integer>' or '--zero-lower-limit=<integer>'      The zero lower limit in milliseconds (see graph below)    \n"
              "                                                            Default : 0                                             \n"
              "    '-x <integer>' or '--zero-upper-limit=<integer>'      The zero upper limit in milliseconds (see graph below)    \n"
              "                                                            Default : 30                                            \n"
              "    '-y <integer>' or '--one-lower-limit=<integer>'       The one lower limit in milliseconds (see graph below)     \n"
              "                                                            Default : 70                                            \n"
              "    '-z <integer>' or '--one-upper-limit=<integer>'       The one upper limit in milliseconds (see graph below)     \n"
              "                                                            Default : 100                                           \n"
              "    '--fields-shifter'                                    Activate fields shifting with default parameters          \n"
              "                                                            Default : Not activated                                 \n"
              "    '-1' or '--tcp-acknowledge-sequence-number-field'     Using the 'Acknowledge Sequence Number field'             \n"
              "                                                            Default : Not activated                                 \n"
              "    '-2' or '--tcp-initial-sequence-number-field'         Using the 'Initial Sequence Number field'                 \n"
              "                                                            Default : Not activated                                 \n"
              "    '-3' or '--ip-packet-identification-field'            Using the 'Packet Identification field'                   \n"
              "                                                            Default : Not activated                                 \n"
              "    '-4' or '--ip-do-not-fragment-field'                  Using the 'Do Not Fragment field'                         \n"
              "                                                            Default : Not activated but used if no other are set    \n"
              "                                                                      and '--fields-shifter' is set                 \n"
              "    'm <mask>' or '--mask <mask>'                         A string representing a 16 bit mask to set which bit of   \n"
              "                                                          the Identification field to use (like '0000000100000000') \n"
              "                                                            Default : '0000000000000001'                            \n"
              "                                                                                     \n"
              "                                                                                     \n"
              "              ^                                                                      \n"
              "    delay     │    one-upper-limit                                                   \n"
              "      in      │    ────────────────────────────────                            \n"
              " milliseconds │                                                                      \n"
              "              │    one-lower-limit                                                   \n"
              "              │    ────────────────────────────────                            \n"
              "              │                                                                      \n"
              "              │    treshold                                                          \n"
              "              │    ────────────────────────────────                            \n"
              "              │                                                                      \n"
              "              │                                                                      \n"
              "              │    ────────────────────────────────                            \n"
              "              │    zero-upper-limit                                                  \n"
              "              │                                                                      \n"
              "              │    ────────────────────────────────                            \n"
              "              │    zero-lower-limit                                                  \n"
              "              │                                                                      \n"
              "            ──│──────────────────────────────────────────────────────>     \n"
              "                                                                                     \n"
              "                                                                                     \n"
              "Exemple:                                                                             \n"
              "    ./stegphy.py -s 'Hello world !'                                                  \n"
              "    ./stegphy.py --receiver --fields-shifter --ip-packet-identification-field        \n")
