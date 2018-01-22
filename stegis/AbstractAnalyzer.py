class AbstractAnalyser:
    steps_for_recomputation = 1
    parameter_name = None
    help_string = None

    def handle_packet(self, packet):
        # Do something with the new packet
        pass
