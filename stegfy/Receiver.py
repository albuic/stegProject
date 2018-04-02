from netfilterqueue import NetfilterQueue
from scapy.all import *

import logging

logger = logging.getLogger('root')


class Receiver:
    __output_file = None
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
    __ip_packet_identification_field_mask = '0000000000000001'
    __tcp_initial_sequence_number_field_mask = '11111111111111111111111111111111'
    __my_file = None
    __next_bit = 0
    __actual_byte = 0


    def __init__(self, output_file, queue_number, time_shifter, fields_shifter, treshold, one_lower_limit, one_upper_limit, zero_lower_limit, zero_upper_limit, tcp_acknowledge_sequence_number_field, tcp_initial_sequence_number_field, ip_packet_identification_field, ip_do_not_fragment_field, ip_packet_identification_field_mask, tcp_initial_sequence_number_field_mask):
        self.__output_file = output_file
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

        if self.__output_file != None:
            self.__my_file = file(self.__output_file, 'w')

        self.handle_packet()


    def handle_packet(self):
        nfqueue = NetfilterQueue()
        nfqueue.bind(self.__queue_number, self.handler)
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            logger.warning('INTERRUPTION : Stopping Receiver.')
        nfqueue.unbind()
        if self.__output_file != None:
            self.__my_file.close()

    def handler(self, packet):
        payload = packet.get_payload()
        pkt = IP(payload)

        # TODO: test if packet is an IP packet and can be used
        if self.__fields_shifter:
            logger.log(5, '****************************')
            logger.debug('Content: packet.id : ' + str(pkt.id))
            logger.debug('Content: packet.chksum : ' + str(pkt.chksum))
            if TCP in pkt:
                logger.debug('Content: packet[TCP].seq : ' + str(pkt[TCP].seq))
                logger.debug('Content: packet[TCP].chksum : ' + str(pkt[TCP].chksum))
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
                            if my_char == "1":
                                new_bit = bin(pkt[TCP].seq)[2:].zfill(32)[index]
                                self.add_next_bit(new_bit, 'TCP Initial Sequence Number field')
                    else:
                        logger.info('Packet is not an initial connection packet, cannot use the TCP Initial Sequence Number field.')
                else:
                    logger.info('Packet is not a TCP packet, cannot use the TCP Initial Sequence Number field.')

            if self.__ip_packet_identification_field:
                for index, my_char in enumerate(self.__ip_packet_identification_field_mask):
                    if my_char == '1':
                        new_bit = bin(pkt.id)[2:].zfill(16)[index]
                        self.add_next_bit(new_bit, 'IP Packet Identification field')
            if self.__ip_do_not_fragment_field:
                self.add_next_bit(bin(pkt[IP].flags)[2], 'IP Do Not Fragment field')
            packet.set_payload(bytes(pkt))

        if self.__time_shifter:
            #TODO
            logger.error('TODO: timeshifter')
            sys.exit(3)

        packet.accept()

    def add_next_bit(self, new_bit, where):
        logger.debug("Receiving bit '" + new_bit + "' in " + where)

        logger.debug("Byte content before : " + str(bin(self.__actual_byte)))

        self.__actual_byte = self.__actual_byte << 1
        if new_bit == '0':
            self.__actual_byte = self.__actual_byte & 0b11111110
        else:
            self.__actual_byte = self.__actual_byte | 0b00000001

        logger.debug("Byte content after : " + str(bin(self.__actual_byte)))

        if logger.getEffectiveLevel() > 24:
            sys.stderr.write("\033[F") # Cursor up one line

        if self.__next_bit < 7:
            logger.log(25, "Receiving: " + bin(self.__actual_byte)[2:].zfill(8)[7 - self.__next_bit : 8])
        else:
            logger.log(25, "Receiving: " + bin(self.__actual_byte)[2:].zfill(8) + "      ('" + chr(self.__actual_byte) + "')\n")

        if self.__next_bit == 7:
            logger.debug("New character received : '" + chr(self.__actual_byte) + "'")

        self.__next_bit += 1
        if self.__next_bit == 8:
            self.__next_bit = 0
            self.__actual_byte = 0
            if self.__output_file != None:
                self.__my_file(str(self.__actual_byte))
