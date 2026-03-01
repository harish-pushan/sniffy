class get_size_pkts(NFPlugin):
    def on_init(self, packet, flow):
        # Called when a flow is first created
        # Initialize a custom variable on the flow object
        flow.udps.NUM_PKTS_UP_TO_128_BYTES = 0
        flow.udps.NUM_PKTS_128_TO_256_BYTES = 0
        flow.udps.NUM_PKTS_256_TO_512_BYTES = 0
        flow.udps.NUM_PKTS_512_TO_1024_BYTES = 0
        flow.udps.NUM_PKTS_1024_TO_1514_BYTES = 0

    def on_update(self, packet, flow):
        # On every update with the flow
        if packet.ip_size:
            if packet.ip_size <= 128:
                flow.udps.NUM_PKTS_UP_TO_128_BYTES += 1
            elif packet.ip_size > 128 and packet.ip_size <= 256:
                flow.udps.NUM_PKTS_128_TO_256_BYTES += 1
            elif packet.ip_size > 256 and packet.ip_size <= 512:
                flow.udps.NUM_PKTS_256_TO_512_BYTES += 1
            elif packet.ip_size > 512 and packet.ip_size <= 1024:
                flow.udps.NUM_PKTS_512_TO_1024_BYTES += 1
            elif packet.ip_size > 1024 and packet.ip_size <= 1514:
                flow.udps.NUM_PKTS_1024_TO_1514_BYTES += 1

    def on_expire(self, flow):
        pass


