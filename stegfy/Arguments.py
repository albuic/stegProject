import getopt
import traceback
import sys

from pathlib import Path

import logging

logger = logging.getLogger('root')


class Arguments:
    verbose = 'normal'
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
    tcp_initial_sequence_number_field_mask = '11111111111111111111111111111111'

    def __init__(self, argv = None):
        if argv is None:
            self.get_arguments(sys.argv)
        else:
            self.get_arguments(argv)


    def get_arguments(self, argv):
        try:
            if argv[0] != "sudo":
                opts, args = getopt.getopt(argv[1:], 'hi:o:q:rst:v:w:x:y:z:1234m:n:', ['help', 'verbose=', 'receiver', 'sender', 'input-file=', 'output-file=', 'queue-number=', 'one-lower-limit=', 'one-upper-limit=', 'input-string=', 'treshold=', 'time-shifter', 'fields-shifter', 'zero-lower-limit=', 'zero-upper-limit=', 'tcp-acknowledge-sequence-number-field', 'tcp-initial-sequence-number-field', 'ip-packet-identification-field', 'ip-do-not-fragment-field', 'ip-mask=', 'tcp-mask='])
            else:
                opts, args = getopt.getopt(argv[2:], 'hi:o:q:rst:v:w:x:y:z:1234m:n:', ['help', 'verbose=', 'receiver', 'sender', 'input-file=', 'output-file=', 'queue-number=', 'one-lower-limit=', 'one-upper-limit=', 'input-string=', 'treshold=', 'time-shifter', 'fields-shifter', 'zero-lower-limit=', 'zero-upper-limit=', 'tcp-acknowledge-sequence-number-field', 'tcp-initial-sequence-number-field', 'ip-packet-identification-field', 'ip-do-not-fragment-field', 'ip-mask=' 'tcp-mask='])
        except getopt.GetoptError as err:
            logger.error(err)
            logger.error('Please see help below')
            Arguments.help()
            sys.exit(2)

        for opt, arg in opts:
            if opt in ('-h', '--help'):
                Arguments.help()
                sys.exit()
            elif opt in ('-v', '--verbose'):
                if arg in ('critical', 'error', 'warning', 'normal', 'info', 'debug', 'trace'):
                    self.verbose = arg
                else:
                    logger.error('Verbose level "' + arg + '" is not an verbose level ("critical", "error", "warning", "normal", "info", "debug", "trace").')
                    sys.exit(2)
            elif opt in ('-i', '--input-file'):
                self.input_file = arg
                if not Path(self.input_file).is_file():
                    logger.error('Input file "' + arg + '" does not exist.')
                    sys.exit(2)
                self.sender = True
            elif opt in ('-o', '--output-file'):
                self.output_file = arg
                self.receiver = True
            elif opt in ('-r', '--receiver'):
                self.receiver = True
            elif opt in ('-s', '--sender'):
                self.sender = True
            elif opt in ('--input-string'):
                self.input_string = arg
                self.sender = True
            elif opt in ('-q', '--queue-number'):
                try:
                    self.queue_number = int(arg)
                except ValueError:
                    logger.error('Queue number "' + arg + '" is not an integer.')
                    sys.exit(2)
            elif opt in ('-y', '--one-lower-limit'):
                try:
                    self.one_lower_limit = int(arg)
                except ValueError:
                    logger.error('One lower limit "' + arg + '" is not an integer.')
                    sys.exit(2)
                self.time_shifter = True
            elif opt in ('-z', '--one-upper-limit'):
                try:
                    self.one_upper_limit = int(arg)
                except ValueError:
                    logger.error('One upper limit "' + arg + '" is not an integer.')
                    sys.exit(2)
                self.time_shifter = True
            elif opt in ('-w', '--zero-lower-limit'):
                try:
                    self.zero_lower_limit = int(arg)
                except ValueError:
                    logger.error('Zero lower limit "' + arg + '" is not an integer.')
                    sys.exit(2)
                self.time_shifter = True
            elif opt in ('-x', '--zero-upper-limit'):
                try:
                    self.zero_upper_limit = int(arg)
                except ValueError:
                    logger.error('Zero upper limit "' + arg + '" is not an integer.')
                    sys.exit(2)
                self.time_shifter = True
            elif opt in ('-t', '--treshold'):
                try:
                    self.treshold = int(arg)
                except ValueError:
                    logger.error('Treshold "' + arg + '" is not an integer.')
                    sys.exit(2)
                self.time_shifter = True
            elif opt in ('-3', '--tcp-acknowledge-sequence-number-field'):
                self.tcp_acknowledge_sequence_number_field = True
                self.fields_shifter = True
            elif opt in ('-4', '--tcp-initial-sequence-number-field'):
                self.tcp_initial_sequence_number_field = True
                self.fields_shifter = True
            elif opt in ('-1', '--ip-packet-identification-field'):
                self.ip_packet_identification_field = True
                self.fields_shifter = True
            elif opt in ('-2', '--ip-do-not-fragment-field'):
                self.ip_do_not_fragment_field = True
                self.fields_shifter = True
            elif opt in ('--time-shifter'):
                self.time_shifter = True
            elif opt in ('--fields-shifter'):
                self.fields_shifter = True
            elif opt in ('-m', '--ip-mask'):
                if len(arg) != 16:
                    logger.error('Mask "' + arg + '" is not a 16 character string representing a IP Packet Identification field mask.')
                    sys.exit(2)
                for my_char in arg:
                    if my_char != '0' and my_char != '1':
                        logger.error('Mask "' + arg + '" contained unkown character(s).')
                        sys.exit(2)
                self.ip_packet_identification_field_mask = arg
                self.fields_shifter = True
            elif opt in ('-n', '--tcp-mask'):
                if len(arg) != 32:
                    logger.error('Mask "' + arg + '" is not a 32 character string representing a TCP Initial Sequence Number field mask.')
                    sys.exit(2)
                for my_char in arg:
                    if my_char != '0' and my_char != '1':
                        logger.error('Mask "' + arg + '" contained unkown character(s).')
                        sys.exit(2)
                self.tcp_initial_sequence_number_field_mask = arg
                self.fields_shifter = True


    def test_and_show_configuration(self):
        # Set log level
        if self.verbose == 'critical':
            logger.setLevel(50)
        elif self.verbose == 'error':
            logger.setLevel(40)
        elif self.verbose == 'warning':
            logger.setLevel(30)
        elif self.verbose == 'normal':
            logger.setLevel(25)
        elif self.verbose == 'info':
            logger.setLevel(20)
        elif self.verbose == 'debug':
            logger.setLevel(10)
        elif self.verbose == 'trace':
            logger.setLevel(5)

        # Testing sender or receiver mode only and log result
        if self.sender and self.receiver:
            logger.error('Cannot use both sender and receiver mode at the same time.')
            sys.exit(2)
        elif self.sender:
            logger.debug("Using sender mode.")
        elif self.receiver:
            logger.debug("Using receiver mode.")
        else:
            logger.warning("Receiver or Sender mode not set.")
            self.receiver = True
            logger.warning("Using receiver mode as default mode.")

        logger.debug('Using queue : "' + str(self.queue_number) + '".')

        # Testing file and input string
        if self.sender:
            if self.input_file != None:
                logger.debug('Using input file : "' + self.input_file + '".')
            elif self.input_string != None:
                if len(self.input_string) > 0:
                    logger.debug('Using input string :\n\n' + self.input_string + '\n')
                else:
                    logger.error('Input string is empty.')
                    sys.exit(2)
            else:
                logger.error('Input file or input string not set.')
                sys.exit(2)
        else:
            if self.output_file != None:
                logger.debug('Using output file : "' + self.output_file + '".')
            else:
                logger.debug('Not using output files.')

        # Testing Time Shifter or Fields Shifter
        if not self.time_shifter and not self.fields_shifter:
            log.warning("Time Shifter or Fields Shifter mode not set.")
            self.time_shifter = True
            log.warning("Using Time Shifter as a default mode.")

        # Testing lower/upper limits and treshold (Time Shifter setup)
        if self.time_shifter:
            if self.zero_lower_limit > self.zero_upper_limit:
                logger.error('The zero lower limit ("' + str(self.zero_lower_limit) + '") is greater than the zero upper limit ("' + str(self.zero_upper_limit) + '").')
                sys.exit(2)
            if self.one_lower_limit > self.one_upper_limit:
                logger.error('The one lower limit ("' + str(self.one_lower_limit) + '") is greater than the one upper limit ("' + str(self.one_upper_limit) + '").')
                sys.exit(2)
            logger.debug("The treshold is " + str(self.treshold) + ".\n"
                  "The one lower limit is " + str(self.one_lower_limit) + ".\n"
                  "The one upper limit is " + str(self.one_upper_limit) + ".\n"
                  "The zero lower limit is " + str(self.zero_lower_limit) + ".\n"
                  "The zero upper limit is " + str(self.zero_upper_limit) + ".\n")
            if self.one_lower_limit < self.treshold:
                logger.warning('The one lower limit ("' + str(self.one_lower_limit) + '") is lower than the treshold ("' + str(self.treshold) + '").')
            if self.zero_upper_limit > self.treshold:
                logger.warning('The zero upper limit ("' + str(self.zero_upper_limit) + '") is greater than the treshold ("' + str(self.treshold) + '").')
            if self.zero_lower_limit == self.zero_upper_limit:
                logger.warning('The zero lower limit equals the zero upper limit ("' + str(self.zero_upper_limit) + '").')
            if self.one_lower_limit == self.one_upper_limit:
                logger.warning('The one lower limit equals the one upper limit ("' + str(self.one_upper_limit) + '").')


        # Testing Fields Shifter setup
        if self.fields_shifter and not self.tcp_initial_sequence_number_field \
                               and not self.tcp_acknowledge_sequence_number_field \
                               and not self.ip_do_not_fragment_field \
                               and not self.ip_packet_identification_field:
            logger.warning("Fields Shifter is set but no fields are set to be used.")
            self.ip_do_not_fragment_field = True
            logger.warning("Using the IP Do Not Fragment Field as a default.")


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
              "    '-v' or '--verbose'                                   Set verbose level: it must be one of 'critical', 'error', \n"
              "                                                          'warning', 'normal', 'info', 'debug', 'trace'             \n"
              "                                                            Default : warning                                       \n"
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
              "    '-1' or '--ip-packet-identification-field'            Using the 'Packet Identification field'                   \n"
              "                                                            Default : Not activated                                 \n"
              "    'm <mask>' or '--ip-mask <mask>'                      A string representing a 16 bit mask to set which bit of   \n"
              "                                                          the IP Identification field to use                        \n"
              "                                                            Default : '0000000000000001'                            \n"
              "    '-2' or '--ip-do-not-fragment-field'                  Using the 'Do Not Fragment field'                         \n"
              "                                                            Default : Not activated but used if no other are set    \n"
              "                                                                      and '--fields-shifter' is set                 \n"
              "    '-3' or '--tcp-acknowledge-sequence-number-field'     Using the 'Acknowledge Sequence Number field'             \n"
              "                                                            Default : Not activated (NOT IMPLEMENTED)               \n"
              "    '-4' or '--tcp-initial-sequence-number-field'         Using the 'Initial Sequence Number field'                 \n"
              "                                                            Default : Not activated                                 \n"
              "    'n <mask>' or '--tcp-mask <mask>'                     A string representing a 32 bit mask to set which bit of   \n"
              "                                                          the TCP Initial Sequence Number field to use              \n"
              "                                                            Default : '11111111111111111111111111111111'            \n"
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
              "    sudo ./stegphy.py -s 'Hello world !'                                             \n"
              "    sudo ./stegphy.py --receiver --fields-shifter --ip-packet-identification-field   \n"
              "    sudo ./main.py --sender --fields-shifter --ip-packet-identification-field --ip-mask '0010000000000001' --ip-do-not-fragment-field --tcp-initial-sequence-number-field --tcp-mask '00001000000000010000000000000001' --input-string 'heywhatsup'\n")
