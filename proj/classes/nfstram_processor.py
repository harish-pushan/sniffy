
from classes.icmp_info import get_icmp_info
from classes.flags_stats import get_flow_flag_stats
from classes.calc_bps import calc_bps


def nfs_processor(streamer):
    for flow in streamer:
        tcp_records = get_flow_flag_stats(flow)
        src_to_dst_bps, dst_to_src_bps, avg_src_to_dst_bps, avg_dst_to_src_bps = calc_bps(
            flow)

        flow_record = {
            "FLOW_ID": flow.id,
            "IPV4_SRC_ADDR": flow.src_ip,
            "L4_SRC_PORT": flow.src_port,
            "IPV4_DST_ADDR": flow.dst_ip,
            "L4_DST_PORT": flow.dst_port,
            "PROTOCOL": flow.protocol,
            "L7_PROTO": flow.application_name,
            "IN_BYTES": flow.dst2src_bytes,
            "IN_PKTS": flow.dst2src_packets,
            "OUT_BYTES": flow.src2dst_bytes,
            "OUT_PKTS": flow.src2dst_packets,
            "FLOW_DURATION_MILLISECONDS": flow.bidirectional_duration_ms,
            "TCP_FLAGS": tcp_records['bidirectional_total'],
            "CLIENT_TCP_FLAGS": tcp_records['client_total'],
            "SERVER_TCP_FLAGS": tcp_records['server_total'],
            "DURATION_IN": flow.dst2src_duration_ms,
            "DURATION_OUT": flow.src2dst_duration_ms,
            "MIN_TTL": flow.udps.min_ttl,
            "MAX_TTL": flow.udps.max_ttl,
            "LONGEST_FLOW_PKT": flow.bidirectional_max_ps,
            "SHORTEST_FLOW_PKT": flow.bidirectional_min_ps,
            "MIN_IP_PKT_LEN": flow.udps.min_ip_pkt_size,
            "MAX_IP_PKT_LEN": flow.udps.max_ip_pkt_size,
            "SRC_TO_DST_SECOND_BYTES": src_to_dst_bps,
            "DST_TO_SRC_SECOND_BYTES": dst_to_src_bps,
            "SRC_TO_DST_AVG_THROUGHPUT": avg_src_to_dst_bps,
            "DST_TO_SRC_AVG_THROUGHPUT": avg_dst_to_src_bps,
            "NUM_PKTS_UP_TO_128_BYTES": flow.udps.NUM_PKTS_UP_TO_128_BYTES,
            "NUM_PKTS_128_TO_256_BYTES": flow.udps.NUM_PKTS_128_TO_256_BYTES,
            "NUM_PKTS_256_TO_512_BYTES": flow.udps.NUM_PKTS_256_TO_512_BYTES,
            "NUM_PKTS_512_TO_1024_BYTES": flow.udps.NUM_PKTS_512_TO_1024_BYTES,
            "NUM_PKTS_1024_TO_1514_BYTES": flow.udps.NUM_PKTS_1024_TO_1514_BYTES,
            "TCP_WIN_MAX_IN": flow.udps.max_tcp_win_in,
            "TCP_WIN_MAX_OUT": flow.udps.max_tcp_win_out,
            "ICMP_TYPE": flow.udps.icmp_type,
            "ICMP_IPV4_TYPE": flow.udps.icmp_ipv4_type,
            "DNS_QUERY_ID": flow.udps.dns_id,
            "DNS_QUERY_TYPE": flow.udps.dns_qt,
            "DNS_TTL_ANSWER": flow.udps.dns_ttl,

        }

        print(f"""
                FLOW_ID                    {flow_record['FLOW_ID']}
                IPV4_SRC_ADDR              {flow_record['IPV4_SRC_ADDR']}
                L4_SRC_PORT                {flow_record['L4_SRC_PORT']}
                IPV4_DST_ADDR              {flow_record['IPV4_DST_ADDR']}
                L4_DST_PORT                {flow_record['L4_DST_PORT']}
                PROTOCOL                   {flow_record['PROTOCOL']}
                L7_PROTO                   {flow_record['L7_PROTO']}
                IN_BYTES                   {flow_record['IN_BYTES']}
                IN_PKTS                    {flow_record['IN_PKTS']}
                OUT_BYTES                  {flow_record['OUT_BYTES']}
                OUT_PKTS                   {flow_record['OUT_PKTS']}
                FLOW_DURATION_MILLISECONDS {flow_record['FLOW_DURATION_MILLISECONDS']}
                TCP_FLAGS                  {flow_record['TCP_FLAGS']}
                CLIENT_FLAGS               {flow_record['CLIENT_TCP_FLAGS']}
                SERVER_FLAGS               {flow_record['SERVER_TCP_FLAGS']}
                DURATION_IN                {flow_record['DURATION_IN']}
                DURATION_OUT               {flow_record['DURATION_OUT']}
                MIN_TTL                    {flow_record['MIN_TTL']}
                MAX_TTL                    {flow_record['MAX_TTL']}
                LONGEST_FLOW_PKT           {flow_record['LONGEST_FLOW_PKT']}
                SHORTEST_FLOW_PKT          {flow_record['SHORTEST_FLOW_PKT']}
                MIN_IP_PKT_LEN             {flow_record['MAX_IP_PKT_LEN']}
                MAX_IP_PKT_LEN             {flow_record['MIN_IP_PKT_LEN']}
                SRC_TO_DST_SECOND_BYTES    {flow_record['SRC_TO_DST_SECOND_BYTES']}
                DST_SRC_TO_SECOND_BYTES    {flow_record['DST_TO_SRC_SECOND_BYTES']}
                SRC_TO_DST_AVG_THROUGHPUT  {flow_record['SRC_TO_DST_AVG_THROUGHPUT']}
                DST_TO_SRC_AVG_THROUGHPUT  {flow_record['DST_TO_SRC_AVG_THROUGHPUT']}
                NUM_PKTS_UP_TO_128_BYTES   {flow_record['NUM_PKTS_UP_TO_128_BYTES']}
                NUM_PKTS_128_TO_256_BYTES  {flow_record['NUM_PKTS_128_TO_256_BYTES']}
                NUM_PKTS_256_TO_512_BYTES  {flow_record['NUM_PKTS_256_TO_512_BYTES']}
                NUM_PKTS_512_TO_1024_BYTES {flow_record['NUM_PKTS_512_TO_1024_BYTES']}
                NUM_PKTS_1024_TO_1514_BYTES{flow_record['NUM_PKTS_1024_TO_1514_BYTES']}
                TCP_WIN_MAX_IN             {flow_record['TCP_WIN_MAX_IN']}
                TCP_WIN_MAX_OUT            {flow_record['TCP_WIN_MAX_OUT']}
                ICMP_TYPE                  {flow_record['ICMP_IPV4_TYPE']}
                ICMP_IPV4_TYPE             {flow_record['ICMP_TYPE']}
                DNS_QUERY_ID               {flow_record['DNS_QUERY_ID']}
                DNS_QUERY_TYPE             {flow_record['DNS_QUERY_TYPE']}
                DNS_TTL_ANSWER             {flow_record['DNS_TTL_ANSWER']}
                """)
