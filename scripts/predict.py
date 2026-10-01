import argparse

import pandas as pd

from sniffy.config import Paths
from sniffy.models.predictor import AttackPredictor


def main() -> None:
    paths = Paths()
    parser = argparse.ArgumentParser(
        description="Classify flows with both model stages"
    )
    parser.add_argument("input_csv")
    parser.add_argument(
        "--stage1", default=str(paths.artifact_dir / "stage1/xgb_v1.pkl")
    )
    parser.add_argument(
        "--stage2", default=str(paths.artifact_dir / "stage2/xgb_v1.pkl")
    )
    parser.add_argument("--output", default="predictions.csv")
    args = parser.parse_args()
    frame = pd.read_csv(args.input_csv)
    predictions = AttackPredictor(args.stage1, args.stage2).predict(frame)
    frame["Prediction"] = predictions
    frame.to_csv(args.output, index=False)
    print(f"Wrote predictions to {args.output}")


if __name__ == "__main__":
    main()
