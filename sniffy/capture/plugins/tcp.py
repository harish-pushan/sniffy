"""TCP window feature plugin."""

import dpkt
from nfstream import NFPlugin


class TcpWindowPlugin(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.max_tcp_win_in = 0
        flow.udps.max_tcp_win_out = 0
        self.on_update(packet, flow)

    def on_update(self, packet, flow):
        if packet.protocol != 6:
            return
        try:
            ip = dpkt.ip.IP(packet.ip_packet)
            if not isinstance(ip.data, dpkt.tcp.TCP):
                return
            field = (
                "max_tcp_win_in" if packet.src_ip == flow.dst_ip else "max_tcp_win_out"
            )
            current = getattr(flow.udps, field)
            setattr(flow.udps, field, max(current, ip.data.win))
        except (dpkt.UnpackError, IndexError, ValueError):
            return
