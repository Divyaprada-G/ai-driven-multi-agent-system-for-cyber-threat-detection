import unittest
import tempfile
import os
from cyber_agents.dataset_validator import DatasetValidator

class TestDatasetValidatorErrors(unittest.TestCase):
    def test_intentional_dataset_errors_detected(self):
        csv_content = """Flow ID,Source IP,Destination IP,Timestamp,Protocol,num_failed_logins,Destination Port,Label
flow-1,192.168.1.10,10.0.0.1,2026-09-18 10:00:00,TCP,0,80,BENIGN
flow-2,,10.0.0.1,2026-09-18 10:00:01,TCP,0,80,BENIGN
flow-3,999.999.999.999,10.0.0.1,2026-09-18 10:00:02,TCP,0,80,BENIGN
flow-4,192.168.1.10,10.0.0.1,2026-09-18 10:00:03,INVALID_PROTO_XYZ,0,80,BENIGN
flow-5,192.168.1.10,10.0.0.1,2026-09-18 10:00:04,TCP,-3,80,BENIGN
flow-6,192.168.1.10,10.0.0.1,NOT_A_TIMESTAMP,TCP,0,80,BENIGN
flow-7,192.168.1.10,10.0.0.1,2026-09-18 10:00:06,TCP,0,80,
flow-1,192.168.1.10,10.0.0.1,2026-09-18 10:00:00,TCP,0,80,BENIGN
"""
        validator = DatasetValidator()
        res = validator.load_and_validate_csv(csv_content, is_raw_content=True)

        self.assertEqual(res["total_rows"], 8)
        self.assertGreater(res["invalid_rows_count"], 0)
        self.assertGreater(res["errors_by_code"]["MISSING_IP"], 0)
        self.assertGreater(res["errors_by_code"]["INVALID_IP"], 0)
        self.assertGreater(res["errors_by_code"]["INVALID_PROTOCOL"], 0)
        self.assertGreater(res["errors_by_code"]["NEGATIVE_FAILED_LOGINS"], 0)
        self.assertGreater(res["errors_by_code"]["INVALID_TIMESTAMP"], 0)
        self.assertGreater(res["errors_by_code"]["MISSING_LABEL"], 0)
        self.assertGreater(res["errors_by_code"]["DUPLICATE_ROW"], 0)
        self.assertLess(res["validation_percentage"], 100.0)
        self.assertGreater(len(res["schema_warnings"]), 0)

if __name__ == "__main__":
    unittest.main()
