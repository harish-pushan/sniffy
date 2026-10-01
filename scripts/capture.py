import argparse

from sniffy.capture.live_capture import PacketCapturer
from sniffy.capture.stream_processor import FlowStreamProcessor
from sniffy.config import Paths


def main() -> None:
    paths = Paths()
    parser = argparse.ArgumentParser(description="Capture NFStream flows to CSV")
    parser.add_argument("--interface", help="Network interface to capture")
    parser.add_argument("--source", help="PCAP file or NFStream source")
    parser.add_argument("--output", default=str(paths.capture_csv))
    parser.add_argument("--label", type=int, choices=(0, 1))
    parser.add_argument("--attack", help="Ground-truth attack class, if known")
    parser.add_argument("--dataset", default="live_capture")
    args = parser.parse_args()

    labels = {"Dataset": args.dataset}
    if args.label is not None:
        labels["Label"] = args.label
    if args.attack is not None:
        labels["Attack"] = args.attack
    capturer = PacketCapturer(args.interface)
    flows = capturer.stream_flows(
        args.source,
        decode_tunnels=True,
        statistical_analysis=True,
        accounting_mode=True,
        n_dissections=20,
    )
    count = FlowStreamProcessor(args.output).process(flows, labels)
    print(f"Wrote {count} flows to {args.output}")


if __name__ == "__main__":
    main()
