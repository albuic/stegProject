from netfilterqueue import NetfilterQueue
from scapy.all import *


class Sender:
    __verbose = False
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
    __ip_packet_identification_field_mask = "1000000000000000"
    __my_file = None
    __next_bit = 0
    __next_byte = 0
    __actual_byte = None
    __actual_bits = None


    def __init__(self, verbose, input_file, input_string, queue_number, time_shifter, fields_shifter, treshold, one_lower_limit, one_upper_limit, zero_lower_limit, zero_upper_limit, tcp_acknowledge_sequence_number_field, tcp_initial_sequence_number_field, ip_packet_identification_field, ip_do_not_fragment_field, ip_packet_identification_field_mask):
        self.__verbose = verbose
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

        if self.__input_file:
            self.__my_file = open(self.__input_file, 'r')
            self.__actual_byte = self.__my_file.read(1)
            if self.__actual_byte == "":
                print("ERROR : File is empty")
                self.__my_file.close()
                sys.exit(3)
        else:
            self.__actual_byte = self.__input_string[0]

        self.__actual_bits = bin(ord(self.__actual_byte))[2:].zfill(8)

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
        if (self.__input_file != None) and (self.__actual_byte == ""):
            print("File has been sent.\nNow sending everything without any encoding.")
        elif (self.__input_string != None) and (len(self.__input_string) < self.__next_byte + 1):
            print("String has been sent.\nNow sending everything without any encoding.")
        else:
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
                            bit_to_send = self.get_next_bit("IP Packet Identification field")

                            char_mask = ''
                            if bit_to_send == 0:
                                for i in range(0, index):
                                    char_mask += '1'
                                char_mask += '0'
                                for i in range(index+1, 16):
                                    char_mask += '1'
                                int_mask = int(char_mask, 2)
                                pkt.id = bit_to_send & int_mask
                            elif bit_to_send == 1:
                                for i in range(0, index):
                                    char_mask += '0'
                                char_mask += '1'
                                for i in range(index+1, 16):
                                    char_mask += '0'
                                int_mask = int(char_mask, 2)
                                pkt.id = bit_to_send | int_mask

                if self.__ip_do_not_fragment_field:
                    # TODO
                    pass
                packet.set_payload(bytes(pkt))

            if self.__time_shifter:
                #TODO
                print("TODO: timeshifter")

        packet.accept()


    def get_next_bit(self, where):
        bit = self.__actual_bits[self.__next_bit]

        if self.__verbose:
            print("Sending bit '" + str(bit) + "' in " + where)
            if self.__next_bit == 7:
                print("New character sended : '" + str(self.__actual_byte) + "'")
        else:
            if self.__next_bit == 0:
                print("Sending: " + str(bit), end='', flush=True)
            elif self.__next_bit == 7:
                print(str(bit) + "      ('" + self.__actual_byte + "')")
            else:
                print(str(bit), end='', flush=True)
            sys.stdout.flush()


        self.__next_bit += 1
        if self.__next_bit == 8:
            self.__next_bit = 0
            if self.__input_file != None:
                self.__actual_byte = self.__my_file.read(1)
                if self.__actual_byte == "":
                    self.__my_file.close()
            else:
                self.__next_byte += 1
                if len(self.__input_string) > self.__next_byte:
                    self.__actual_byte = self.__input_string[self.__next_byte]
            self.__actual_bits = bin(ord(self.__actual_byte))[2:].zfill(8)

        return 0 if bit == '0' else 1
