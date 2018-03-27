from netfilterqueue import NetfilterQueue
from scapy.all import *


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

    __my_file = None
    __next_bit = 0
    __next_byte = 0
    __actual_byte = None
    __actual_bits = None


    def __init__(self, input_file, input_string, queue_number, time_shifter, fields_shifter, treshold, one_lower_limit, one_upper_limit, zero_lower_limit, zero_upper_limit, tcp_acknowledge_sequence_number_field, tcp_initial_sequence_number_field, ip_packet_identification_field, ip_do_not_fragment_field):
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

        if self.__input_file:
            self.__my_file = open(self.__input_file, 'r')
            self.__actual_byte = self.__my_file.read(1)
            if self.__actual_byte == "":
                print("ERROR : File is empty")
                self.__my_file.close()
                sys.exit(3)
        else:
            self.__actual_byte = self.__input_string[0]

        self.__actual_bits = bin(ord(self.__actual_byte)).zfill(8)

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
                bit_to_send = self.get_next_bit()
                pkt.id = bit_to_send
                print("Sending bit '" + bit_to_send + "' in IP Packet Identification field")
            if self.__ip_do_not_fragment_field:
                # TODO
                pass
            packet.set_payload(bytes(pkt))

        if self.__time_shifter:
            #TODO
            print("TODO: timeshifter")

        packet.accept()

    def get_next_bit(self):
        bit = ''
        bits = ''

        bit = self.__actual_bits[self.__next_bit]
        self.__next_bit += 1
        if self.__next_bit == 8:
            self.__next_bit = 0
            if self.__input_file:
                self.__actual_byte = self.__my_file.read(1)
                if self.__actual_byte == "":
                    self.__my_file.close()
                    print("File has been sent.\nNow sending everything without any encoding.")
            else:
                self.__next_byte += 1
                if len(self.__input_string) > self.__next_byte:
                    print("String has been sent.\nNow sending everything without any encoding.")
                else:
                    self.__actual_byte = self.__input_string[self.__next_byte]
            self.__actual_bits = bin(ord(self.__actual_byte)).zfill(8)

        return 0 if bit == b'0' else 1
