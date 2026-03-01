from nfs_stream import NFPlugin


class get_ttl_value(NFPlugin):

    def on_init(self, packet, flow):
        # TTL is on the 8th byte offset
        ttl = packet.ip_packet[8]
        flow.udps.min_ttl = ttl
        flow.udps.max_ttl = ttl

    def on_update(self, packet, flow):
        if len(packet.ip_packet) > 8:
            ttl = packet.ip_packet[8]
            if ttl > flow.udps.max_ttl:
                flow.udps.max_ttl = ttl
            elif ttl < flow.udps.min_ttl:
                flow.udps.min_ttl = ttl

    def on_expire(self, flow):
        pass
