from nfstream import NFStreamer, NFPlugin
import dpkt

import netifaces as ni
SOURCE_IP = ni.ifaddresses('wlan0')[ni.AF_INET][0]['addr']
print(SOURCE_IP)

class get_tcp_window(NFPlugin):
    def on_init(self, packet, flow):
        flow.udps.tcp_win = 0 
        flow.udps.max_tcp_win_in = 0 
        flow.udps.max_tcp_win_out = 0

    def on_update(self,packet,flow):
        if packet.protocol != 6:
            return
        try:
            # parse full IP packet
            ip = dpkt.ip.IP(packet.ip_packet)
            # make sure it's UDP
            if not isinstance(ip.data, dpkt.tcp.TCP):
                return
            tcp = ip.data
            # Anything that is an actual connection should have some bytes in it so we jst need something 
            if len(tcp.data) <= 2:
                return
            tcp_data = dpkt.tcp.TCP(tcp.data)  
            if packet.src_ip == SOURCE_IP:
                flow.udps.max_tcp_win_in = tcp_data.win
                print(f"source tcp win:{flow.udps.max_tcp_win_in}")
                print(f"dst tcp win:{flow.udps.max_tcp_win_out}")
            else:
                flow.udps.max_tcp_win_out = tcp_data.win
                print(f"source tcp win:{flow.udps.max_tcp_win_in}")
                print(f"dst tcp win:{flow.udps.max_tcp_win_out}")

        except:
            pass


streamer = NFStreamer(
    source="capture.pcap",
    udps=[get_tcp_window()]

)

for flow in streamer:
    pass
    





