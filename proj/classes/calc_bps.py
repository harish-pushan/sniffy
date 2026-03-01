def calc_bps(flow):
    # avoid division by zero
    src_duration_s = max(flow.src2dst_duration_ms, 1) / 1000
    dst_duration_s = max(flow.dst2src_duration_ms, 1) / 1000

    src_to_dst_bps = (flow.src2dst_bytes * 8) / src_duration_s
    dst_to_src_bps = (flow.dst2src_bytes * 8) / dst_duration_s

    src_to_dst_bps = round(src_to_dst_bps, 1)
    dst_to_src_bps = round(dst_to_src_bps, 1)

    # since only one value exists, avg == current
    avg_src_to_dst_bps = src_to_dst_bps
    avg_dst_to_src_bps = dst_to_src_bps

    return src_to_dst_bps, dst_to_src_bps, avg_src_to_dst_bps, avg_dst_to_src_bps


