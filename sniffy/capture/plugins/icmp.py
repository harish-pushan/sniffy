"""ICMP type feature plugin."""

import dpkt
from nfstream import NFPlugin


class IcmpPlugin(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.icmp_type = 0
        flow.udps.icmp_ipv4_type = 0
        self.on_update(packet, flow)

    def on_update(self, packet, flow):
        if packet.protocol != 1:
            return
        try:
            ip = dpkt.ip.IP(packet.ip_packet)
            if not isinstance(ip.data, dpkt.icmp.ICMP):
                return
            flow.udps.icmp_ipv4_type = ip.data.type
            flow.udps.icmp_type = ip.data.type * 256 + ip.data.code
        except (dpkt.UnpackError, IndexError, ValueError):
            return
