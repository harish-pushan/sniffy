def get_icmp_info(flow):
    icmp_ipv4_type = 0
    if flow.protocol == 1:
        icmp_ipv4_type = flow.application_name

    return icmp_ipv4_type


