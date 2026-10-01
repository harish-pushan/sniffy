"""IPv4 TTL range feature plugin."""

from nfstream import NFPlugin


class TtlPlugin(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.min_ttl = 0
        flow.udps.max_ttl = 0
        self.on_update(packet, flow)

    def on_update(self, packet, flow):
        raw_packet = packet.ip_packet
        if len(raw_packet) < 9:
            return
        ttl = raw_packet[8]
        if flow.udps.min_ttl == 0:
            flow.udps.min_ttl = ttl
        else:
            flow.udps.min_ttl = min(flow.udps.min_ttl, ttl)
        flow.udps.max_ttl = max(flow.udps.max_ttl, ttl)
