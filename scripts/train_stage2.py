import argparse

from sniffy.config import Paths, TrainerHyperparameters
from sniffy.models.stage2_trainer import AttackTypeTrainer


def main() -> None:
    paths = Paths()
    parser = argparse.ArgumentParser(description="Train the attack-type classifier")
    parser.add_argument("directory", nargs="?", default=str(paths.attack_dir))
    parser.add_argument(
        "--artifact", default=str(paths.artifact_dir / "stage2/xgb_v1.pkl")
    )
    parser.add_argument("--estimators", type=int, default=100)
    args = parser.parse_args()
    trainer = AttackTypeTrainer(
        hyperparams=TrainerHyperparameters(n_estimators=args.estimators),
        artifact_path=args.artifact,
    )
    trainer.fit_directory(args.directory)
    for metrics in trainer.metrics:
        print(metrics)


if __name__ == "__main__":
    main()
