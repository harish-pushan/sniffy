from nfstream import NFStreamer, NFPlugin
import dpkt


from classes.calc_bps import calc_bps
from classes.dns_values import get_dns_value
from classes.flags_stats import get_flow_flag_stats
from classes.get_diff_pkt_sizes import get_size_pkts
from classes.icmp_info import get_icmp_info
from classes.icmp_values import get_icmp_vales
from classes.ip_pkt_len import ip_pkt_len_return
from classes.nfstram_processor import nfs_processor
from classes.tcp_win import get_tcp_window
from classes.ttl_values import get_ttl_value

streamer = NFStreamer(
    source="capture.pcap",
    decode_tunnels=True,
    statistical_analysis=True,
    accounting_mode=True,
    n_dissections=20,
    udps=[ip_pkt_len_return(), get_size_pkts(), get_ttl_value(),
          get_icmp_vales(), get_dns_value(), get_tcp_window()]
)
while True:
    try:
        nfs_processor(streamer)
    except KeyboardInterrupt:
        exit("Stopeed the capture")
