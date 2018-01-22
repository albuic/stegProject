import pcap


if __name__ == '__main__':
    sniffer = pcap.pcap(name=None, promisc=True, immediate=True)
    print sniffer
    addr = lambda pkt, offset: '.'.join(str(ord(pkt[i])) for i in xrange(offset, offset + 4)).ljust(16)

    for ts, pkt in sniffer:
        print ts, '\tSRC', addr(pkt, sniffer.dloff + 12), '\tDST', addr(pkt, sniffer.dloff + 16)

