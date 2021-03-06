#!/usr/bin/python3

import sys

from Arguments import *
from Receiver import *
from Sender import *

import log

logger = log.setup_custom_logger('root')


if __name__ == "__main__":
    logger.debug('Starting stegfy')

    logger.debug('Getting arguments (call Arguments())')
    my_arguments = Arguments()
    logger.debug('Testing configuration (my_arguments.test_and_show_configuration())')
    my_arguments.test_and_show_configuration()

    if my_arguments.receiver:
        logger.info('Starting receiver mode (Receiver(...))')
        receiver = Receiver(my_arguments.output_file, my_arguments.queue_number, my_arguments.time_shifter, my_arguments.fields_shifter, my_arguments.treshold, my_arguments.one_lower_limit, my_arguments.one_upper_limit, my_arguments.zero_lower_limit, my_arguments.zero_upper_limit, my_arguments.tcp_acknowledge_sequence_number_field, my_arguments.tcp_initial_sequence_number_field, my_arguments.ip_packet_identification_field, my_arguments.ip_do_not_fragment_field, my_arguments.ip_packet_identification_field_mask, my_arguments.tcp_initial_sequence_number_field_mask)
    if my_arguments.sender:
        logger.info('Starting sender mode (Sender(...))')
        sender = Sender(my_arguments.input_file, my_arguments.input_string, my_arguments.queue_number, my_arguments.time_shifter, my_arguments.fields_shifter, my_arguments.treshold, my_arguments.one_lower_limit, my_arguments.one_upper_limit, my_arguments.zero_lower_limit, my_arguments.zero_upper_limit, my_arguments.tcp_acknowledge_sequence_number_field, my_arguments.tcp_initial_sequence_number_field, my_arguments.ip_packet_identification_field, my_arguments.ip_do_not_fragment_field, my_arguments.ip_packet_identification_field_mask, my_arguments.tcp_initial_sequence_number_field_mask)

    sys.exit(0)
