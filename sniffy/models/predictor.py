"""Cascade stage-one detections into stage-two attack classifications."""

from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sniffy.schema import DROP_COLS_STAGE1, DROP_COLS_STAGE2


class AttackPredictor:
    def __init__(self, stage1_path: str | Path, stage2_path: str | Path):
        self.stage1 = self._load(stage1_path)
        self.stage2 = self._load(stage2_path)

    @staticmethod
    def _load(path: str | Path) -> dict:
        loaded = joblib.load(path)
        if isinstance(loaded, dict) and "model" in loaded:
            return loaded
        return {"model": loaded, "classes": [], "feature_names": []}

    @staticmethod
    def _features(frame: pd.DataFrame, drop_columns: list[str], names: list[str]):
        features = frame.drop(columns=drop_columns, errors="ignore").copy()
        features = features.apply(pd.to_numeric, errors="coerce")
        features.replace([np.inf, -np.inf], np.nan, inplace=True)
        features.fillna(0, inplace=True)
        features = features.clip(upper=1e8, lower=-1e8)
        if names:
            features = features.reindex(columns=names, fill_value=0)
        return features

    def predict(self, features: pd.DataFrame) -> pd.Series:
        output = pd.Series("benign", index=features.index, dtype=object)
        stage1_x = self._features(
            features, [*DROP_COLS_STAGE1, "Label"], self.stage1["feature_names"]
        )
        attack_mask = self.stage1["model"].predict(stage1_x) == 1
        if not attack_mask.any():
            return output

        stage2_x = self._features(
            features.loc[attack_mask],
            [*DROP_COLS_STAGE2, "Attack"],
            self.stage2["feature_names"],
        )
        predicted = np.asarray(self.stage2["model"].predict(stage2_x))
        if predicted.ndim > 1:
            predicted = predicted.argmax(axis=1)
        predicted = predicted.astype(int)
        classes = self.stage2["classes"]
        if classes:
            predicted = np.asarray(classes, dtype=object)[predicted]
        output.loc[attack_mask] = predicted
        return output
