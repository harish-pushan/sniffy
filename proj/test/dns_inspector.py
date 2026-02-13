from nfs_stream import NFPlugin, NFStreamer


class DNSInspector:
    def on_init(self, packet, flow):
        flow.udps.dns_query_id = 0
        flow.udps.dns_query_type = 0
        flow.udps.dns_ttl_answer = 0

    def on_update(self, packet, flow):

