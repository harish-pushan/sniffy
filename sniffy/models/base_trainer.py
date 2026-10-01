"""Shared incremental XGBoost training implementation."""

from abc import ABC, abstractmethod
from collections import Counter
import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
import xgboost as xgb

from sniffy.config import TrainerHyperparameters
from sniffy.data.loader import DirectoryScanner
from sniffy.data.preprocessing import FeaturePreprocessor

logger = logging.getLogger(__name__)


class XGBIncrementalTrainer(ABC):
    def __init__(
        self,
        preprocessor: FeaturePreprocessor,
        hyperparams: TrainerHyperparameters,
        artifact_path: str | Path,
    ):
        self.preprocessor = preprocessor
        self.hyperparams = hyperparams
        self.artifact_path = Path(artifact_path)
        self.source_directory: Path | None = None
        self.model: xgb.XGBClassifier | None = None
        self.feature_names_: list[str] = []
        self.classes_: list[object] = []
        self.metrics: list[dict[str, object]] = []

    @abstractmethod
    def scale_pos_weight_source(self) -> str:
        """Return the dataset directory used for this stage's class balance."""

    @abstractmethod
    def _build_model(self, class_counts: Counter) -> xgb.XGBClassifier:
        """Create the stage-specific classifier."""

    def _class_counts(self, directory: Path) -> Counter:
        counts: Counter = Counter()
        for file_path in DirectoryScanner.list_csv_files(directory):
            for chunk in pd.read_csv(
                file_path, usecols=[self.preprocessor.target_col], chunksize=500_000
            ):
                counts.update(chunk[self.preprocessor.target_col].dropna().tolist())
        if not counts:
            raise ValueError(f"No target values found in {directory}")
        return counts

    def _prepare_batch(self, dataframe: pd.DataFrame):
        x_train, x_test, y_train, y_test = self.preprocessor.transform(dataframe)
        if self.feature_names_:
            x_train = x_train.reindex(columns=self.feature_names_, fill_value=0)
            x_test = x_test.reindex(columns=self.feature_names_, fill_value=0)
        else:
            self.feature_names_ = list(x_train.columns)
        return x_train, x_test, y_train, y_test

    def _compute_metrics(self, y_test, y_pred, y_proba=None) -> dict[str, object]:
        y_pred = np.asarray(y_pred)
        if y_pred.ndim > 1:
            y_pred = y_pred.argmax(axis=1)
        average = "binary" if len(set(y_test)) == 2 else "weighted"
        metrics: dict[str, object] = {
            "accuracy": accuracy_score(y_test, y_pred),
            "precision": precision_score(
                y_test, y_pred, average=average, zero_division=0
            ),
            "recall": recall_score(y_test, y_pred, average=average, zero_division=0),
            "f1": f1_score(y_test, y_pred, average=average, zero_division=0),
            "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        }
        if y_proba is not None and len(set(y_test)) == 2:
            metrics["roc_auc"] = roc_auc_score(y_test, y_proba)
        else:
            metrics["roc_auc"] = None
        return metrics

    def fit_directory(self, directory: str | Path) -> xgb.XGBClassifier:
        self.source_directory = Path(directory)
        files = DirectoryScanner.list_csv_files(self.source_directory)
        if not files:
            raise ValueError(f"No CSV files found in {self.source_directory}")
        class_counts = self._class_counts(Path(self.scale_pos_weight_source()))
        self.model = self._build_model(class_counts)
        self.metrics = []
        has_fitted_batch = False

        for file_path in files:
            for chunk in pd.read_csv(file_path, chunksize=500_000):
                x_train, x_test, y_train, y_test = self._prepare_batch(chunk)
                if not self.classes_ and self.preprocessor.target_col == "Attack":
                    self.classes_ = sorted(class_counts, key=str)
                    label_map = {
                        label: index for index, label in enumerate(self.classes_)
                    }
                    y_train = y_train.map(label_map)
                    y_test = y_test.map(label_map)
                elif self.preprocessor.target_col == "Attack":
                    label_map = {
                        label: index for index, label in enumerate(self.classes_)
                    }
                    y_train = y_train.map(label_map)
                    y_test = y_test.map(label_map)

                sample_weight = self._sample_weights(y_train, class_counts)
                self.model.fit(
                    x_train,
                    y_train,
                    eval_set=[(x_test, y_test)],
                    xgb_model=self.model.get_booster() if has_fitted_batch else None,
                    sample_weight=sample_weight,
                    verbose=False,
                )
                has_fitted_batch = True
                y_pred = self.model.predict(x_test)
                y_proba = self.model.predict_proba(x_test)
                positive_proba = y_proba[:, 1] if y_proba.shape[1] == 2 else None
                metrics = self._compute_metrics(y_test, y_pred, positive_proba)
                metrics["file"] = str(file_path)
                self.metrics.append(metrics)
                logger.info("Metrics for %s: %s", file_path.name, metrics)

        self.artifact_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {
                "model": self.model,
                "classes": self.classes_,
                "feature_names": self.feature_names_,
            },
            self.artifact_path,
        )
        return self.model

    def _sample_weights(self, y_train: pd.Series, class_counts: Counter):
        if self.preprocessor.target_col != "Attack":
            return None
        total = sum(class_counts.values())
        class_count = max(len(class_counts), 1)
        encoded_counts = Counter(
            {index: class_counts[label] for index, label in enumerate(self.classes_)}
        )
        return y_train.map(
            lambda label: total / (class_count * encoded_counts[label])
        ).to_numpy()
