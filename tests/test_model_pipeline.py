import tempfile
import unittest
from pathlib import Path

import pandas as pd

from sniffy.config import TrainerHyperparameters
from sniffy.models.predictor import AttackPredictor
from sniffy.models.stage1_trainer import BinaryAttackTrainer
from sniffy.models.stage2_trainer import AttackTypeTrainer


class ModelPipelineTests(unittest.TestCase):
    def test_train_both_stages_and_predict_attack_types(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = []
            attacks = []
            for index in range(60):
                label = int(index >= 20)
                attack = ("scan" if index % 2 else "dos") if label else "benign"
                row = {
                    "feature": index % 7,
                    "Label": label,
                    "Attack": attack,
                    "Dataset": "synthetic",
                    "IPV4_SRC_ADDR": "192.0.2.1",
                    "IPV4_DST_ADDR": "192.0.2.2",
                }
                records.append(row)
                if label:
                    attacks.append(row)

            stage1_dir = root / "stage1_data"
            stage2_dir = root / "stage2_data"
            stage1_dir.mkdir()
            stage2_dir.mkdir()
            pd.DataFrame(records).to_csv(stage1_dir / "data.csv", index=False)
            pd.DataFrame(attacks).to_csv(stage2_dir / "attacks.csv", index=False)
            params = TrainerHyperparameters(n_estimators=2, test_size=0.25)
            stage1_path = root / "artifacts/stage1.pkl"
            stage2_path = root / "artifacts/stage2.pkl"

            BinaryAttackTrainer(
                hyperparams=params, artifact_path=stage1_path
            ).fit_directory(stage1_dir)
            AttackTypeTrainer(
                hyperparams=params, artifact_path=stage2_path
            ).fit_directory(stage2_dir)
            predictions = AttackPredictor(stage1_path, stage2_path).predict(
                pd.DataFrame(records[:5])
            )

            self.assertEqual(len(predictions), 5)
            self.assertTrue(set(predictions).issubset({"benign", "dos", "scan"}))
            self.assertNotEqual(stage1_path, stage2_path)


if __name__ == "__main__":
    unittest.main()
