from nfstream import NFStreamer, NFPlugin


class MyCustomFeature(NFPlugin):
    def on_init(self, packet, flow):
        """Called when a flow is first created."""
        # Initialize a custom variable on the flow object
        flow.udps.packet_count_over_100 = 0

        # Check the first packet
        if packet.ip_size > 100:
            flow.udps.packet_count_over_100 += 1

    def on_update(self, packet, flow):
        """Called for every subsequent packet in the flow."""
        if packet.ip_size > 100:
            flow.udps.packet_count_over_100 += 1

    def on_expire(self, flow):
        """Called when the flow expires (optional cleanup)."""
        pass


def nfs_processor(streamer):
    ip_pkt_lengths = []
    for flow in streamer:
        ip_pkt_lengths.append(flow.ip_size)
        flow_record = {
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
            "DURATION_IN": flow.dst2src_duration_ms,
            "DURATION_OUT": flow.src2dst_duration_ms,
            "LONGEST_FLOW_PKT": flow.bidirectional_min_ps,
            "SHORTEST_FLOW_PKT": flow.bidirectional_max_ps,
            "MIN_IP_PKT_LEN": min(ip_pkt_lengths),
            "MAX_IP_PKT_LEN": max(ip_pkt_lengths)


        }
        print(f"""
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
    accounting_mode=True
)
while True:
    try:
        nfs_processor(streamer)
    except KeyboardInterrupt:
        print("nfs_parser_stopped")
        exit()
