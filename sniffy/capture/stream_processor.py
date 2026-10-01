"""Serialize NFStream flow objects as canonical schema rows."""

import csv
from pathlib import Path

from sniffy.schema import COLUMNS


def _value(source, name: str, default=0):
    return getattr(source, name, default)


class FlowStreamProcessor:
    def __init__(self, output_csv: str | Path):
        self.output_csv = Path(output_csv)
        self.output_csv.parent.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def flow_record(flow, labels: dict[str, object] | None = None) -> dict[str, object]:
        labels = labels or {}
        custom = getattr(flow, "udps", None)
        if custom is None:
            custom = object()
        source_to_destination_bytes = _value(flow, "src2dst_bytes")
        destination_to_source_bytes = _value(flow, "dst2src_bytes")
        source_duration = max(_value(flow, "src2dst_duration_ms"), 1) / 1000
        destination_duration = max(_value(flow, "dst2src_duration_ms"), 1) / 1000
        if _value(flow, "protocol") == 6:
            client_flags = sum(
                _value(flow, f"src2dst_{flag}_packets")
                for flag in ("syn", "cwr", "ece", "urg", "ack", "psh", "rst", "fin")
            )
            server_flags = sum(
                _value(flow, f"dst2src_{flag}_packets")
                for flag in ("syn", "cwr", "ece", "urg", "ack", "psh", "rst", "fin")
            )
        else:
            client_flags = server_flags = 0

        record = {
            "IPV4_SRC_ADDR": _value(flow, "src_ip", ""),
            "L4_SRC_PORT": _value(flow, "src_port"),
            "IPV4_DST_ADDR": _value(flow, "dst_ip", ""),
            "L4_DST_PORT": _value(flow, "dst_port"),
            "PROTOCOL": _value(flow, "protocol"),
            "L7_PROTO": _value(flow, "application_name", 0),
            "IN_BYTES": destination_to_source_bytes,
            "IN_PKTS": _value(flow, "dst2src_packets"),
            "OUT_BYTES": source_to_destination_bytes,
            "OUT_PKTS": _value(flow, "src2dst_packets"),
            "TCP_FLAGS": client_flags + server_flags,
            "CLIENT_TCP_FLAGS": client_flags,
            "SERVER_TCP_FLAGS": server_flags,
            "FLOW_DURATION_MILLISECONDS": _value(flow, "bidirectional_duration_ms"),
            "DURATION_IN": _value(flow, "dst2src_duration_ms"),
            "DURATION_OUT": _value(flow, "src2dst_duration_ms"),
            "MIN_TTL": _value(custom, "min_ttl"),
            "MAX_TTL": _value(custom, "max_ttl"),
            "LONGEST_FLOW_PKT": _value(flow, "bidirectional_max_ps"),
            "SHORTEST_FLOW_PKT": _value(flow, "bidirectional_min_ps"),
            "MIN_IP_PKT_LEN": _value(custom, "min_ip_pkt_size"),
            "MAX_IP_PKT_LEN": _value(custom, "max_ip_pkt_size"),
            "SRC_TO_DST_SECOND_BYTES": round(
                source_to_destination_bytes * 8 / source_duration, 1
            ),
            "DST_TO_SRC_SECOND_BYTES": round(
                destination_to_source_bytes * 8 / destination_duration, 1
            ),
            "RETRANSMITTED_IN_BYTES": _value(flow, "dst2src_retransmitted_bytes"),
            "RETRANSMITTED_IN_PKTS": _value(flow, "dst2src_retransmitted_packets"),
            "RETRANSMITTED_OUT_BYTES": _value(flow, "src2dst_retransmitted_bytes"),
            "RETRANSMITTED_OUT_PKTS": _value(flow, "src2dst_retransmitted_packets"),
            "SRC_TO_DST_AVG_THROUGHPUT": round(
                source_to_destination_bytes * 8 / source_duration, 1
            ),
            "DST_TO_SRC_AVG_THROUGHPUT": round(
                destination_to_source_bytes * 8 / destination_duration, 1
            ),
            "NUM_PKTS_UP_TO_128_BYTES": _value(custom, "NUM_PKTS_UP_TO_128_BYTES"),
            "NUM_PKTS_128_TO_256_BYTES": _value(custom, "NUM_PKTS_128_TO_256_BYTES"),
            "NUM_PKTS_256_TO_512_BYTES": _value(custom, "NUM_PKTS_256_TO_512_BYTES"),
            "NUM_PKTS_512_TO_1024_BYTES": _value(custom, "NUM_PKTS_512_TO_1024_BYTES"),
            "NUM_PKTS_1024_TO_1514_BYTES": _value(
                custom, "NUM_PKTS_1024_TO_1514_BYTES"
            ),
            "TCP_WIN_MAX_IN": _value(custom, "max_tcp_win_in"),
            "TCP_WIN_MAX_OUT": _value(custom, "max_tcp_win_out"),
            "ICMP_TYPE": _value(custom, "icmp_type"),
            "ICMP_IPV4_TYPE": _value(custom, "icmp_ipv4_type"),
            "DNS_QUERY_ID": _value(custom, "dns_id"),
            "DNS_QUERY_TYPE": _value(custom, "dns_qt"),
            "DNS_TTL_ANSWER": _value(custom, "dns_ttl"),
            "FTP_COMMAND_RET_CODE": _value(custom, "ftp_command_ret_code"),
            "Label": labels.get("Label", ""),
            "Attack": labels.get("Attack", ""),
            "Dataset": labels.get("Dataset", "live_capture"),
        }
        return {column: record.get(column, "") for column in COLUMNS}

    def process(self, flows, labels: dict[str, object] | None = None) -> int:
        has_header = self.output_csv.exists() and self.output_csv.stat().st_size > 0
        count = 0
        with self.output_csv.open("a", newline="", encoding="utf-8") as output:
            writer = csv.DictWriter(output, fieldnames=COLUMNS, extrasaction="ignore")
            if not has_header:
                writer.writeheader()
            for flow in flows:
                writer.writerow(self.flow_record(flow, labels))
                count += 1
        return count
