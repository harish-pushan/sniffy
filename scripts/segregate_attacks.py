import argparse

from sniffy.config import Paths
from sniffy.data.segregation import AttackSegregator


def main() -> None:
    paths = Paths()
    parser = argparse.ArgumentParser(
        description="Create and verify the attack-only stage-two dataset"
    )
    parser.add_argument("source", nargs="?", default=str(paths.split_dir))
    parser.add_argument("destination", nargs="?", default=str(paths.attack_dir))
    args = parser.parse_args()
    segregator = AttackSegregator()
    count = segregator.create(args.source, args.destination)
    if not segregator.verify(args.destination):
        raise SystemExit("Attack dataset verification failed")
    print(f"Created {count} attack-only CSV files in {args.destination}")


if __name__ == "__main__":
    main()
