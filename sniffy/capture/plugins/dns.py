"""DNS query and answer feature plugin."""

import dpkt
from nfstream import NFPlugin


class DnsPlugin(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.dns_id = 0
        flow.udps.dns_qt = 0
        flow.udps.dns_ttl = 0
        self.on_update(packet, flow)

    def on_update(self, packet, flow):
        if packet.protocol != 17:
            return
        try:
            ip = dpkt.ip.IP(packet.ip_packet)
            if not isinstance(ip.data, dpkt.udp.UDP) or len(ip.data.data) < 12:
                return
            dns = dpkt.dns.DNS(ip.data.data)
            flow.udps.dns_id = dns.id
            if dns.qd:
                flow.udps.dns_qt = dns.qd[0].type
            for answer in dns.an:
                if answer.type == dpkt.dns.DNS_A:
                    flow.udps.dns_ttl = answer.ttl
                    break
        except (dpkt.UnpackError, IndexError, UnicodeDecodeError, ValueError):
            return
