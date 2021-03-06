from netfilterqueue import NetfilterQueue
from scapy.all import *
from time import sleep
from random import randint

import logging

logger = logging.getLogger('root')


class Sender:
    __input_file = None
    __input_string = None
    __queue_number = 10
    __time_shifter = False
    __fields_shifter = False
    __treshold = 50
    __one_lower_limit = 70
    __one_upper_limit = 100
    __zero_lower_limit = 0
    __zero_upper_limit = 30
    __tcp_acknowledge_sequence_number_field = False
    __tcp_initial_sequence_number_field = False
    __ip_packet_identification_field = False
    __ip_do_not_fragment_field = False
    __ip_packet_identification_field_mask = '1000000000000000'
    __tcp_initial_sequence_number_field_mask = '11111111111111111111111111111111'
    __my_file = None
    __next_bit = 0
    __next_byte = 0
    __actual_byte = None
    __actual_bits = None
    __first_packet = True
    __string_or_file_sended = False
    __last_null_byte_sended = False


    def __init__(self, input_file, input_string, queue_number, time_shifter, fields_shifter, treshold, one_lower_limit, one_upper_limit, zero_lower_limit, zero_upper_limit, tcp_acknowledge_sequence_number_field, tcp_initial_sequence_number_field, ip_packet_identification_field, ip_do_not_fragment_field, ip_packet_identification_field_mask, tcp_initial_sequence_number_field_mask):
        self.__input_file = input_file
        self.__input_string = input_string
        self.__queue_number = queue_number
        self.__time_shifter = time_shifter
        self.__fields_shifter = fields_shifter
        self.__treshold = treshold
        self.__one_lower_limit = one_lower_limit
        self.__one_upper_limit = one_upper_limit
        self.__zero_lower_limit = zero_lower_limit
        self.__zero_upper_limit = zero_upper_limit
        self.__tcp_acknowledge_sequence_number_field = tcp_acknowledge_sequence_number_field
        self.__tcp_initial_sequence_number_field = tcp_initial_sequence_number_field
        self.__ip_packet_identification_field = ip_packet_identification_field
        self.__ip_do_not_fragment_field = ip_do_not_fragment_field
        self.__ip_packet_identification_field_mask = ip_packet_identification_field_mask
        self.__tcp_initial_sequence_number_field_mask = tcp_initial_sequence_number_field_mask

        if self.__input_file:
            self.__my_file = open(self.__input_file, 'r')
        self.__actual_byte = '\x02'

        self.__actual_bits = bin(ord(self.__actual_byte))[2:].zfill(8)

        self.handle_packet()


    def handle_packet(self):
        nfqueue = NetfilterQueue()
        nfqueue.bind(self.__queue_number, self.handler)
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            logger.warning('INTERRUPTION : Stopping Sender.')
        nfqueue.unbind()

    def handler(self, packet):
        if not self.__string_or_file_sended or not self.__last_null_byte_sended or not self.__next_bit == 8:
            payload = packet.get_payload()
            try:
                pkt = IP(payload)
            except:
                logger.warning('Packet is not an IP packet')
                packet.accept()


            if self.__fields_shifter:
                # Verbose modes
                logger.log(5, '********** Before **********')
                logger.debug('Before: packet.id : ' + str(pkt.id))
                logger.debug('Before: packet.chksum : ' + str(pkt.chksum))
                if TCP in pkt:
                    logger.debug('Before: packet[TCP].seq : ' + str(pkt[TCP].seq) + '  =  ' + str(bin(pkt[TCP].seq)))
                    logger.debug('Before: packet[TCP].chksum : ' + str(pkt[TCP].chksum) + '  =  ' + str(bin(pkt[TCP].chksum)))
                if logger.getEffectiveLevel() < 6:
                    pkt.show()
                logger.log(5, '****************************')

                if self.__tcp_acknowledge_sequence_number_field:
                    # TODO: Probably not as it must use bouncing (and so another machine)
                    logger.error('"--tcp-acknowledge-sequence-number-field" not implemented.')
                    sys.exit(3)

                if self.__tcp_initial_sequence_number_field:
                    if TCP in pkt:
                        # Testing if packet is the first packet of a connection and can be used (0x02 is the bitmap SYN flag)
                        if pkt[TCP].flags & 0x02:
                            logger.info('Packet is an initial connection packet, using the TCP Initial Sequence Number field.')
                            for index, my_char in enumerate(self.__tcp_initial_sequence_number_field_mask):
                                if my_char == '1':
                                    bit_to_send = self.get_next_bit('TCP Initial Sequence Number field')

                                    if bit_to_send == 0:
                                        pkt[TCP].seq = pkt[TCP].seq & ( (2**32-1)-(2**(31-index)) )
                                    elif bit_to_send == 1:
                                        pkt[TCP].seq = pkt[TCP].seq | (2**(31-index))
                                    else:
                                        pass # Nothing to send
                            del pkt[TCP].chksum
                            pkt = pkt.__class__(bytes(pkt))
                        else:
                            logger.info('Packet is not an initial connection packet, cannot use the TCP Initial Sequence Number field.')
                    else:
                        logger.info('Packet is not a TCP packet, cannot use the TCP Initial Sequence Number field.')

                if self.__ip_packet_identification_field:
                    for index, my_char in enumerate(self.__ip_packet_identification_field_mask):
                        if my_char == '1':
                            bit_to_send = self.get_next_bit('IP Packet Identification field')

                            if bit_to_send == 0:
                                pkt.id = pkt.id & ( (2**16-1)-(2**(15-index)) )
                            elif bit_to_send == 1:
                                pkt.id = pkt.id | (2**(15-index))
                            else:
                                pass # Nothing to send

                if self.__ip_do_not_fragment_field:
                    bit_to_send = self.get_next_bit('IP Do Not Fragment field')

                    if bit_to_send == 0:
                        pkt[IP].flags = 0
                    elif bit_to_send == 1:
                        pkt[IP].flags = 2
                    else:
                        pass # Nothing to send

                del pkt.chksum
                pkt = pkt.__class__(bytes(pkt))

                packet.set_payload(bytes(pkt))

                # Verbose modes
                logger.log(5, '*********** After ***********')
                logger.debug('After: packet.id : ' + str(pkt.id))
                logger.debug('After: packet.chksum : ' + str(pkt.chksum))
                if TCP in pkt:
                    logger.debug('After: packet[TCP].seq : ' + str(pkt[TCP].seq))
                    logger.debug('After: packet[TCP].chksum : ' + str(pkt[TCP].chksum))
                if logger.getEffectiveLevel() < 6:
                    pkt.show()
                logger.log(5, '*****************************')

            if self.__time_shifter and not self.__first_packet:
                bit_to_send = self.get_next_bit('Time Shifter')

                if bit_to_send == 0:
                    delay = randint(self.__zero_lower_limit, self.__zero_upper_limit)/1000
                    logger.debug('Using a delay of "' + str(delay) + '" seconds.')
                    sleep(delay)
                elif bit_to_send == 1:
                    delay = randint(self.__one_lower_limit, self.__one_upper_limit)/1000
                    logger.debug('Using a delay of "' + str(delay) + '" seconds.')
                    sleep(delay)
                else:
                    pass # Nothing to send

        packet.accept()

        self.__first_packet = False


    def get_next_bit(self, where):
        if self.__next_bit <= 7:
            bit = self.__actual_bits[self.__next_bit]
            logger.debug('Sending bit "' + str(bit) + '" in ' + where)

        if logger.getEffectiveLevel() > 24:
            sys.stderr.write('\033[F') # Cursor up one line
        if self.__next_bit < 7:
            logger.log(25, 'Sending: ' + self.__actual_bits[0 : self.__next_bit + 1])
        else:
            logger.log(25, 'Sending: ' + self.__actual_bits[0 : self.__next_bit + 1] + '  ("' + self.__actual_byte + '")\n')

        if self.__next_bit == 7:
            logger.debug('New character sended : "' + str(self.__actual_byte) + '"')
        #sys.stderr.flush()

        self.__next_bit += 1
        if self.__next_bit >= 8:
            self.__next_bit = 0
            if not self.__string_or_file_sended:
                if self.__input_file != None:
                    self.__actual_byte = self.__my_file.read(1)
                    if self.__actual_byte == '':
                        self.__my_file.close()
                        self.__string_or_file_sended = True
                else:
                    if len(self.__input_string) > self.__next_byte:
                        self.__actual_byte = self.__input_string[self.__next_byte]
                    else:
                        self.__string_or_file_sended = True
                    self.__next_byte += 1

            if self.__string_or_file_sended:
                if not self.__last_null_byte_sended:
                    if self.__input_file != None:
                        logger.log(25, 'File has been sent. Now sending a "EOT" (end of transmission) byte then nothing.\n')
                    elif self.__input_string != None:
                        logger.log(25, 'String has been sent. Now sending a "EOT" (end of transmission) byte then nothing.\n')
                    logger.debug('Set closing character ("\\x04") and __last_null_byte_sended to "True".')
                    self.__actual_byte = '\x04'

                    self.__last_null_byte_sended = True
                else:
                    logger.debug('File or String has been sent. Nothing to send.')
                    self.__next_bit = 8
                    return 3

            self.__actual_bits = bin(ord(self.__actual_byte))[2:].zfill(8)

        return 0 if bit == '0' else 1
