from nfs_stream import NFPlugin


class get_icmp_vales(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.icmp_type = 0
        flow.udps.icmp_ipv4_type = packet.ip_packet[0]
        flow.udps.icmp_code = packet.ip_packet[1]

    def on_update(self, packet, flow):
        if len(packet.ip_packet) > 0:
            flow.udps.icmp_type = (
                (flow.udps.icmp_ipv4_type * 258) + flow.udps.icmp_code)

    def on_expire(self, flow):
        pass
