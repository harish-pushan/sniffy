"""Lazy wrappers for packet and NFStream flow capture."""

from pathlib import Path


class PacketCapturer:
    def __init__(
        self, interface: str | None = None, output_file: str | Path | None = None
    ):
        self.interface = interface
        self.output_file = Path(output_file) if output_file else None

    def capture_packets(self):
        try:
            from pyshark import LiveCapture
        except ImportError as error:
            raise RuntimeError("Packet capture requires pyshark") from error
        capture = LiveCapture(
            interface=self.interface,
            output_file=str(self.output_file) if self.output_file else None,
        )
        try:
            yield from capture.sniff_continuously()
        finally:
            capture.close()

    def stream_flows(self, source: str | None = None, **options):
        try:
            from nfstream import NFStreamer
            from sniffy.capture.plugins.dns import DnsPlugin
            from sniffy.capture.plugins.icmp import IcmpPlugin
            from sniffy.capture.plugins.packet_size import PacketSizePlugin
            from sniffy.capture.plugins.tcp import TcpWindowPlugin
            from sniffy.capture.plugins.ttl import TtlPlugin
        except ImportError as error:
            raise RuntimeError("Flow capture requires nfstream and dpkt") from error

        capture_source = source or self.interface
        if not capture_source:
            raise ValueError("Provide a source file or network interface")
        streamer = NFStreamer(
            source=capture_source,
            udps=[
                DnsPlugin(),
                IcmpPlugin(),
                PacketSizePlugin(),
                TcpWindowPlugin(),
                TtlPlugin(),
            ],
            **options,
        )
        yield from streamer
