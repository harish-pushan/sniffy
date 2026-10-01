"""Packet-size histogram and IP-length feature plugin."""

from nfstream import NFPlugin


class PacketSizePlugin(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.NUM_PKTS_UP_TO_128_BYTES = 0
        flow.udps.NUM_PKTS_128_TO_256_BYTES = 0
        flow.udps.NUM_PKTS_256_TO_512_BYTES = 0
        flow.udps.NUM_PKTS_512_TO_1024_BYTES = 0
        flow.udps.NUM_PKTS_1024_TO_1514_BYTES = 0
        flow.udps.min_ip_pkt_size = 0
        flow.udps.max_ip_pkt_size = 0
        self.on_update(packet, flow)

    def on_update(self, packet, flow):
        packet_size = packet.ip_size
        if not packet_size:
            return
        if packet_size <= 128:
            flow.udps.NUM_PKTS_UP_TO_128_BYTES += 1
        elif packet_size <= 256:
            flow.udps.NUM_PKTS_128_TO_256_BYTES += 1
        elif packet_size <= 512:
            flow.udps.NUM_PKTS_256_TO_512_BYTES += 1
        elif packet_size <= 1024:
            flow.udps.NUM_PKTS_512_TO_1024_BYTES += 1
        elif packet_size <= 1514:
            flow.udps.NUM_PKTS_1024_TO_1514_BYTES += 1

        if flow.udps.min_ip_pkt_size == 0:
            flow.udps.min_ip_pkt_size = packet_size
        else:
            flow.udps.min_ip_pkt_size = min(flow.udps.min_ip_pkt_size, packet_size)
        flow.udps.max_ip_pkt_size = max(flow.udps.max_ip_pkt_size, packet_size)
