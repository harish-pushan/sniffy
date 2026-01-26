from nfstream import NFStreamer, NFPlugin


class MyCustomFeature(NFPlugin):
    def on_init(self, packet, flow):
        """Called when a flow is first created."""
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


def get_flow_flag_stats(flow):
    if flow.protocol == 6:

        # Calculate Client (Source to Destination)
        client_flags = (flow.src2dst_syn_packets + flow.src2dst_cwr_packets +
                        flow.src2dst_ece_packets + flow.src2dst_urg_packets +
                        flow.src2dst_ack_packets + flow.src2dst_psh_packets +
                        flow.src2dst_rst_packets + flow.src2dst_fin_packets)

        # Calculate Server (Destination to Source)
        server_flags = (flow.dst2src_syn_packets + flow.dst2src_cwr_packets +
                        flow.dst2src_ece_packets + flow.dst2src_urg_packets +
                        flow.dst2src_ack_packets + flow.dst2src_psh_packets +
                        flow.dst2src_rst_packets + flow.dst2src_fin_packets)

        # Calculate Bidirectional (Total)
        total_flags = (flow.bidirectional_syn_packets + flow.bidirectional_cwr_packets +
                       flow.bidirectional_ece_packets + flow.bidirectional_urg_packets +
                       flow.bidirectional_ack_packets + flow.bidirectional_psh_packets +
                       flow.bidirectional_rst_packets + flow.bidirectional_fin_packets)

        return {
            "client_total": client_flags,
            "server_total": server_flags,
            "bidirectional_total": total_flags
        }

    else:
        return {
            "client_total": 0,
            "server_total": 0,
            "bidirectional_total": 0
        }


def nfs_processor(streamer):
    for flow in streamer:
        tcp_records = get_flow_flag_stats(flow)
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
            "LONGEST_FLOW_PKT": flow.bidirectional_max_ps,
            "SHORTEST_FLOW_PKT": flow.bidirectional_min_ps,
            "MIN_IP_PKT_LEN": flow.udps.min_ip_pkt_size,
            "MAX_IP_PKT_LEN": flow.udps.max_ip_pkt_size,
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
        LONGEST_FLOW_PKT           {flow_record['LONGEST_FLOW_PKT']}
        SHORTEST_FLOW_PKT          {flow_record['SHORTEST_FLOW_PKT']}
        MIN_IP_PKT_LEN             {flow_record['MAX_IP_PKT_LEN']}
        MAX_IP_PKT_LEN             {flow_record['MIN_IP_PKT_LEN']}
        """)


streamer = NFStreamer(
    source="capture.pcap",
    decode_tunnels=True,
    statistical_analysis=True,
    accounting_mode=True,
    udps=MyCustomFeature()
)
while True:
    try:
        nfs_processor(streamer)
    except KeyboardInterrupt:
        exit("Stopeed the capture")
