from nfs_stream import NFPlugin


class ip_pkt_len_return(NFPlugin):
    def on_init(self, packet, flow):
        # Called when a flow is first created
        # Initialize a custom variable on the flow object
        flow.udps.ip_pkt_len = []
        flow.udps.min_ip_pkt_size = 0
        flow.udps.max_ip_pkt_size = 0

    def on_update(self, packet, flow):
        if packet.ip_size:
            flow.udps.ip_pkt_len.append(packet.ip_size)
            flow.udps.min_ip_pkt_size = min(flow.udps.ip_pkt_len)
            flow.udps.max_ip_pkt_size = max(flow.udps.ip_pkt_len)

    def on_expire(self, flow):
        pass
