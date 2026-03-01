from nfs_stream import NFPlugin
import dpkt


class get_dns_value(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.dns_id = 0
        flow.udps.dns_qt = 0
        flow.udps.dns_ttl = 0

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
            dns_ans = dns.an
            for i in dns_ans:
                # this is a list of multiple attr so we need to use a for loop to use the type attr same for the ttl
                flow.udps.dns_qt = i.type
                if flow.udps.dns_qt == 1:
                    flow.udps.dns_ttl = i.ttl
                break

            # Dns query id like the numbers for the id
            flow.udps.dns_id = dns.id

        except (dpkt.UnpackError, IndexError):
            pass
        except (UnicodeDecodeError):
            pass
