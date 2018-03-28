from netfilterqueue import NetfilterQueue
from scapy.all import *


class Receiver:
    __verbose = 0
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
    __my_file = None
    __next_bit = 0
    __actual_byte = 0


    def __init__(self, verbose, output_file, queue_number, time_shifter, fields_shifter, treshold, one_lower_limit, one_upper_limit, zero_lower_limit, zero_upper_limit, tcp_acknowledge_sequence_number_field, tcp_initial_sequence_number_field, ip_packet_identification_field, ip_do_not_fragment_field, ip_packet_identification_field_mask):
        self.__verbose = verbose
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

        if self.__output_file != None:
            self.__my_file = file(self.__output_file, 'w')

        self.handle_packet()


    def handle_packet(self):
        nfqueue = NetfilterQueue()
        nfqueue.bind(self.__queue_number, self.handler)
        try:
            nfqueue.run()
        except KeyboardInterrupt:
            print('')
            print("INTERRUPTION : Stopping Sender.")
        nfqueue.unbind()
        if self.__output_file != None:
            self.__my_file.close()

    def handler(self, packet):
        payload = packet.get_payload()
        pkt = IP(payload)

        # TODO: test if packet is an IP packet and can be used
        if self.__fields_shifter:
            if self.__tcp_acknowledge_sequence_number_field:
                # TODO: test if tcp packet
                pass
            if self.__tcp_initial_sequence_number_field:
                # TODO: test if tcp packet
                pass
            if self.__ip_packet_identification_field:
                for index, my_char in enumerate(self.__ip_packet_identification_field_mask):
                    if my_char == "1":
                        new_bit = bin(pkt.id)[2:].zfill(16)[index]
                        self.add_next_bit(new_bit, "IP Packet Identification field")
            if self.__ip_do_not_fragment_field:
                # TODO
                pass
            packet.set_payload(bytes(pkt))

        if self.__time_shifter:
            #TODO
            print("TODO: timeshifter")

        packet.accept()

    def add_next_bit(self, new_bit, where):
        if self.__verbose > 1:
            print("byte content before : " + str(bin(self.__actual_byte)))

        self.__actual_byte = self.__actual_byte << 1
        if new_bit == '0':
            self.__actual_byte = self.__actual_byte & 0b11111110
        else:
            self.__actual_byte = self.__actual_byte | 0b00000001

        if self.__verbose > 1:
            print("Receiving bit '" + new_bit + "' in " + where)
            print("byte content after : " + str(bin(self.__actual_byte)))
            if self.__next_bit == 7:
                print("New character received : '" + chr(self.__actual_byte) + "'")
        else:
            if self.__next_bit == 0:
                print("Receiving: " + new_bit, end='', flush=True)
            elif self.__next_bit == 7:
                print(new_bit + "      ('" + chr(self.__actual_byte) + "')")
            else:
                print(new_bit, end='', flush=True)
            sys.stdout.flush()

        self.__next_bit += 1
        if self.__next_bit == 8:
            self.__next_bit = 0
            if self.__output_file != None:
                self.__my_file(str(self.__actual_byte))
