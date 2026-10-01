import argparse

from sniffy.config import Paths
from sniffy.data.loader import DatasetSplitter


def main() -> None:
    paths = Paths()
    parser = argparse.ArgumentParser(description="Split a CSV into manageable chunks")
    parser.add_argument("source", nargs="?", default=str(paths.dataset))
    parser.add_argument("destination", nargs="?", default=str(paths.split_dir))
    parser.add_argument("--chunksize", type=int, default=500_000)
    args = parser.parse_args()
    count = DatasetSplitter(args.chunksize).split(args.source, args.destination)
    print(f"Wrote {count} dataset chunks to {args.destination}")


if __name__ == "__main__":
    main()
