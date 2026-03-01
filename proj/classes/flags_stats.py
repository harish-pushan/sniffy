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



