"""Binary benign-versus-attack trainer."""

from collections import Counter
from pathlib import Path

import xgboost as xgb

from sniffy.config import TrainerHyperparameters
from sniffy.data.preprocessing import FeaturePreprocessor
from sniffy.models.base_trainer import XGBIncrementalTrainer
from sniffy.schema import DROP_COLS_STAGE1, TARGET_STAGE1


class BinaryAttackTrainer(XGBIncrementalTrainer):
    def __init__(
        self,
        preprocessor: FeaturePreprocessor | None = None,
        hyperparams: TrainerHyperparameters | None = None,
        artifact_path: str | Path = "artifacts/stage1/xgb_v1.pkl",
    ):
        params = hyperparams or TrainerHyperparameters()
        super().__init__(
            preprocessor
            or FeaturePreprocessor(
                DROP_COLS_STAGE1,
                TARGET_STAGE1,
                test_size=params.test_size,
                random_state=params.random_state,
            ),
            params,
            artifact_path,
        )

    def scale_pos_weight_source(self) -> str:
        if self.source_directory is None:
            raise RuntimeError("fit_directory must set a source directory first")
        return str(self.source_directory)

    def _build_model(self, class_counts: Counter) -> xgb.XGBClassifier:
        if len(class_counts) != 2 or class_counts.get(1, 0) == 0:
            raise ValueError("Stage one requires Label values 0 and 1")
        params = self.hyperparams
        return xgb.XGBClassifier(
            objective="binary:logistic",
            eval_metric="auc",
            n_estimators=params.n_estimators,
            max_depth=params.max_depth,
            learning_rate=params.learning_rate,
            subsample=params.subsample,
            colsample_bytree=params.colsample_bytree,
            reg_alpha=params.reg_alpha,
            reg_lambda=params.reg_lambda,
            scale_pos_weight=class_counts[0] / class_counts[1],
            random_state=params.random_state,
        )
