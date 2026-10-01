"""Portable paths and training defaults."""

from dataclasses import dataclass, field
import os
from pathlib import Path


@dataclass(frozen=True)
class Paths:
    root: Path = field(
        default_factory=lambda: Path(os.environ.get("SNIFFY_HOME", Path.cwd()))
        .expanduser()
        .resolve()
    )

    @property
    def dataset(self) -> Path:
        return Path(os.environ.get("SNIFFY_DATASET", self.root / "data/dataset.csv"))

    @property
    def split_dir(self) -> Path:
        return Path(os.environ.get("SNIFFY_SPLIT_DIR", self.root / "data/splitted"))

    @property
    def attack_dir(self) -> Path:
        return Path(os.environ.get("SNIFFY_ATTACK_DIR", self.root / "data/attacks"))

    @property
    def artifact_dir(self) -> Path:
        return Path(os.environ.get("SNIFFY_ARTIFACT_DIR", self.root / "artifacts"))

    @property
    def capture_csv(self) -> Path:
        return Path(
            os.environ.get("SNIFFY_CAPTURE_CSV", self.root / "data/capture.csv")
        )


@dataclass(frozen=True)
class TrainerHyperparameters:
    n_estimators: int = 100
    max_depth: int = 6
    learning_rate: float = 0.05
    subsample: float = 0.8
    colsample_bytree: float = 0.8
    reg_alpha: float = 0.1
    reg_lambda: float = 1.0
    test_size: float = 0.25
    random_state: int = 42
