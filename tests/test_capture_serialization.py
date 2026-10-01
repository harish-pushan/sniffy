import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

import pandas as pd

from sniffy.capture.stream_processor import FlowStreamProcessor
from sniffy.schema import COLUMNS


class CaptureSerializationTests(unittest.TestCase):
    def test_flow_is_written_in_canonical_schema_order(self):
        flow = SimpleNamespace(
            src_ip="192.0.2.1",
            src_port=1234,
            dst_ip="192.0.2.2",
            dst_port=80,
            protocol=6,
            application_name=7,
            src2dst_bytes=100,
            dst2src_bytes=50,
            src2dst_packets=2,
            dst2src_packets=1,
            src2dst_duration_ms=100,
            dst2src_duration_ms=100,
            bidirectional_duration_ms=200,
            bidirectional_max_ps=60,
            bidirectional_min_ps=40,
            udps=SimpleNamespace(min_ttl=64, max_ttl=64),
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "flows.csv"
            self.assertEqual(
                FlowStreamProcessor(output).process(
                    [flow], {"Label": 1, "Attack": "scan"}
                ),
                1,
            )
            frame = pd.read_csv(output)
            self.assertEqual(list(frame.columns), COLUMNS)
            self.assertEqual(frame.loc[0, "Attack"], "scan")
            self.assertEqual(frame.loc[0, "MAX_TTL"], 64)


if __name__ == "__main__":
    unittest.main()
