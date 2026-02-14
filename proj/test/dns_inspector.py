from nfstream import NFStreamer, NFPlugin
import dpkt


class DNSIdPlugin(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.dns_id = None

    def on_update(self, packet, flow):
        # only UDP
        if packet.protocol != 17:
            return
        try:
            # parse full IP packet
            ip = dpkt.ip.IP(packet.ip_packet)
            # make sure it's UDP
            if not isinstance(ip.data, dpkt.udp.UDP):
                return
            udp = ip.data
            # DNS header min size = 12 bytes
            if len(udp.data) <= 12:
                return

            dns = dpkt.dns.DNS(udp.data)
            flow.udps.dns_id = dns.id

        except (dpkt.UnpackError, IndexError):
            pass


streamer = NFStreamer(
    source="capture.pcap",
    udps=[DNSIdPlugin()]
)

for flow in streamer:
    if flow.udps.dns_id is not None:
        print(flow.src_ip, "->", flow.dst_ip, "DNS ID:", flow.udps.dns_id)
