import tempfile
import unittest
from pathlib import Path

import pandas as pd

from sniffy.data.loader import DatasetSplitter
from sniffy.data.preprocessing import FeaturePreprocessor
from sniffy.data.segregation import AttackSegregator
from sniffy.schema import COLUMNS, DROP_COLS_STAGE1, TARGET_STAGE1


class DataPipelineTests(unittest.TestCase):
    def test_schema_is_unique_and_preprocessor_uses_canonical_case(self):
        self.assertEqual(len(COLUMNS), 46)
        self.assertEqual(len(COLUMNS), len(set(COLUMNS)))
        frame = pd.DataFrame(
            {
                "IPV4_SRC_ADDR": ["1.1.1.1"] * 4,
                "Dataset": ["a"] * 4,
                "Attack": ["benign"] * 4,
                "feature": [1, 2, 3, 4],
                "Label": [0, 0, 1, 1],
            }
        )
        x_train, _, y_train, _ = FeaturePreprocessor(
            DROP_COLS_STAGE1, TARGET_STAGE1, test_size=0.5
        ).transform(frame)
        self.assertEqual(list(x_train.columns), ["feature"])
        self.assertEqual(set(y_train), {0, 1})

    def test_splitter_writes_every_chunk_in_schema_order(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source.csv"
            pd.DataFrame({"Label": [0, 1, 0], "feature": [4, 5, 6]}).to_csv(
                source, index=False
            )
            count = DatasetSplitter(chunksize=2, columns=["feature", "Label"]).split(
                source, root / "split"
            )
            self.assertEqual(count, 2)
            self.assertEqual(
                [
                    len(pd.read_csv(path))
                    for path in sorted((root / "split").glob("*.csv"))
                ],
                [2, 1],
            )

    def test_attack_segregation_creates_and_verifies_attack_only_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            pd.DataFrame({"Label": [0, 1, 1], "Attack": ["n", "a", "b"]}).to_csv(
                source / "data.csv", index=False
            )
            segregator = AttackSegregator(chunksize=1)
            self.assertEqual(segregator.create(source, root / "attacks"), 1)
            self.assertTrue(segregator.verify(root / "attacks"))
            self.assertEqual(
                pd.read_csv(root / "attacks" / "sec_data.csv")["Label"].tolist(),
                [1, 1],
            )


if __name__ == "__main__":
    unittest.main()
