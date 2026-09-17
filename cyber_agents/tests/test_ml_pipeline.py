"""
Unit Tests for Machine Learning Pipeline, Models, Preprocessing, and Threat Detection Agent Integration.
"""
import unittest
import os
import tempfile
import json
import shutil

from cyber_agents.dataset_validator import validate_file_safety, DatasetValidator
from cyber_agents.preprocessor import PreprocessingPipeline, train_test_split_dataset
from cyber_agents.ml_models import RandomForest, IsolationForest
from cyber_agents.ml_pipeline import MLPipeline
from cyber_agents.threat_detection_agent import ThreatDetectionAgent


class TestMLPipeline(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.sample_csv_content = (
            "Flow ID,Source IP,Destination IP,Destination Port,Timestamp,Flow Duration,Flow Packets/s,Total Fwd Packets,Label\n"
            "flow-1,10.0.0.1,10.0.0.2,80,2026-09-17T10:00:00,1000,10.5,5,BENIGN\n"
            "flow-2,10.0.0.1,10.0.0.2,80,2026-09-17T10:00:01,1200,12.0,6,BENIGN\n"
            "flow-3,10.0.0.3,10.0.0.2,80,2026-09-17T10:00:02,1100,11.2,5,BENIGN\n"
            "flow-4,10.0.0.4,10.0.0.2,80,2026-09-17T10:00:03,1050,10.8,5,BENIGN\n"
            "flow-5,192.168.1.5,10.0.0.2,22,2026-09-17T10:00:04,500,850.0,20,PortScan\n"
            "flow-6,192.168.1.5,10.0.0.2,23,2026-09-17T10:00:05,480,920.0,22,PortScan\n"
            "flow-7,192.168.1.5,10.0.0.2,443,2026-09-17T10:00:06,510,880.0,18,PortScan\n"
            "flow-8,192.168.1.9,10.0.0.2,80,2026-09-17T10:00:07,9500,50.0,150,DDoS\n"
            "flow-9,192.168.1.9,10.0.0.2,80,2026-09-17T10:00:08,9800,55.0,160,DDoS\n"
            "flow-10,192.168.1.9,10.0.0.2,80,2026-09-17T10:00:09,9200,48.0,140,DDoS\n"
        )
        self.csv_path = os.path.join(self.temp_dir, "test_dataset.csv")
        with open(self.csv_path, "w", encoding="utf-8") as f:
            f.write(self.sample_csv_content)

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_file_safety_validation(self):
        """Tests that dangerous file uploads and directory traversals are strictly blocked."""
        # Forbidden extensions
        safe, msg = validate_file_safety("malware.exe")
        self.assertFalse(safe)
        self.assertIn("forbidden", msg.lower())

        safe, msg = validate_file_safety("payload.sh")
        self.assertFalse(safe)

        safe, msg = validate_file_safety("script.py")
        self.assertFalse(safe)

        # Path traversal
        safe, msg = validate_file_safety("../../../etc/passwd.csv")
        self.assertFalse(safe)
        self.assertIn("traversal", msg.lower())

        # Valid CSV
        safe, msg = validate_file_safety("legitimate_data.csv")
        self.assertTrue(safe)

    def test_dataset_schema_and_identifier_isolation(self):
        """Tests schema detection, missing values, and identifier column isolation."""
        validator = DatasetValidator()
        res = validator.load_and_validate_csv(self.csv_path)

        self.assertEqual(res["total_rows"], 10)
        self.assertEqual(res["detected_label"], "Label")
        # Ensure Flow ID, Source IP, Destination IP, Timestamp are detected as identifiers
        self.assertTrue(any("ip" in id_col.lower() or "flow" in id_col.lower() for id_col in res["identifier_columns"]))
        # Suggested features should NOT include identifier columns or label
        self.assertNotIn("Source IP", res["suggested_features"])
        self.assertNotIn("Destination IP", res["suggested_features"])
        self.assertNotIn("Flow ID", res["suggested_features"])
        self.assertNotIn("Timestamp", res["suggested_features"])
        self.assertNotIn("Label", res["suggested_features"])
        self.assertIn("Destination Port", res["suggested_features"])
        self.assertIn("Total Fwd Packets", res["suggested_features"])

    def test_data_leakage_prevention(self):
        """Tests that preprocessor parameters are computed strictly on training data."""
        validator = DatasetValidator()
        validated = validator.load_and_validate_csv(self.csv_path)

        split = train_test_split_dataset(
            rows=validated["rows"],
            headers=validated["headers"],
            selected_features=validated["suggested_features"],
            label_column="Label",
            train_ratio=0.7,
            random_seed=42,
            stratify=False
        )

        self.assertGreater(len(split["X_train"]), 0)
        self.assertGreater(len(split["X_test"]), 0)
        self.assertEqual(len(split["X_train"]) + len(split["X_test"]), 10)

        # Ensure pipeline is fitted
        pipeline: PreprocessingPipeline = split["pipeline"]
        self.assertTrue(pipeline.is_fitted)
        self.assertEqual(len(pipeline.feature_means), len(validated["suggested_features"]))

    def test_random_forest_training_and_evaluation(self):
        """Tests Random Forest training, held-out evaluation, metrics, and confusion matrix."""
        pipeline = MLPipeline(artifacts_dir=os.path.join(self.temp_dir, "artifacts"))
        artifact = pipeline.train_random_forest(
            dataset_input=self.csv_path,
            label_column="Label",
            train_ratio=0.7,
            random_seed=42,
            n_estimators=10,
            max_depth=5
        )

        self.assertEqual(artifact["modelType"], "RANDOM_FOREST")
        metrics = artifact["evaluationMetrics"]
        self.assertIsNotNone(metrics)
        self.assertIn("accuracy", metrics)
        self.assertIn("macroF1", metrics)
        self.assertIn("confusionMatrix", metrics)
        self.assertIn("featureImportances", metrics)

        # Confusion matrix checks
        cm = metrics["confusionMatrix"]
        self.assertGreater(len(cm["labels"]), 0)
        self.assertEqual(cm["totalSamples"], artifact["testRows"])

        # Check artifact files created on disk
        model_dir = os.path.join(self.temp_dir, "artifacts", artifact["modelId"])
        self.assertTrue(os.path.exists(os.path.join(model_dir, "metadata.json")))
        self.assertTrue(os.path.exists(os.path.join(model_dir, "preprocessor.json")))

    def test_isolation_forest_anomaly_detection(self):
        """Tests Isolation Forest training and anomaly score calculations."""
        pipeline = MLPipeline(artifacts_dir=os.path.join(self.temp_dir, "artifacts"))
        artifact = pipeline.train_isolation_forest(
            dataset_input=self.csv_path,
            contamination=0.1,
            n_estimators=15,
            random_seed=42
        )

        self.assertEqual(artifact["modelType"], "ISOLATION_FOREST")
        self.assertIn("anomalyThreshold", artifact)
        self.assertEqual(artifact["trainRows"], 10)

    def test_inference_prediction(self):
        """Tests real inference returning threat category, severity, confidence, and explainability."""
        pipeline = MLPipeline(artifacts_dir=os.path.join(self.temp_dir, "artifacts"))
        rf_art = pipeline.train_random_forest(
            dataset_input=self.csv_path,
            label_column="Label",
            train_ratio=0.7,
            random_seed=42,
            n_estimators=10
        )

        sample_scan = {
            "Destination Port": 22,
            "Flow Duration": 500.0,
            "Flow Packets/s": 900.0,
            "Total Fwd Packets": 25
        }
        res = pipeline.predict_sample(sample_scan, model_id=rf_art["modelId"])
        self.assertEqual(res["status"], "SUCCESS")
        self.assertIn("threatCategory", res)
        self.assertIn("severity", res)
        self.assertIn("confidence", res)
        self.assertIn("anomalyScore", res)
        self.assertIn("importantContributingFeatures", res)
        self.assertIn("modelVersion", res)
        self.assertGreater(res["confidence"], 0.0)

    def test_threat_detection_agent_integration(self):
        """Tests that ThreatDetectionAgent integrates with MLPipeline and separates rule from ML."""
        agent = ThreatDetectionAgent(artifacts_dir=os.path.join(self.temp_dir, "artifacts"))

        # Train a model in temp dir
        agent.pipeline.train_random_forest(
            dataset_input=self.csv_path,
            label_column="Label",
            n_estimators=10
        )
        agent.active_model_id = agent._find_best_model_id()

        raw_events = [
            {
                "event_id": "EVT-TEST-001",
                "event_type": "Port Scan Attack",
                "severity": "HIGH",
                "description": "Port scan from 192.168.1.5",
                "indicators": {"port": 22, "burst_frequency": 9.5}
            }
        ]

        result = agent.detect(raw_events)
        self.assertTrue(result["threat_detected"])
        self.assertIn("overall_severity", result)
        self.assertEqual(result["rule_based_count"], 1)
        self.assertEqual(len(result["rule_based_findings"]), 1)

        ml_analysis = result["machine_learning_analysis"]
        self.assertIn("predicted_class", ml_analysis)
        self.assertIn("confidence", ml_analysis)
        self.assertIn("anomaly_score", ml_analysis)
        self.assertIn("model_benchmark_metrics", ml_analysis)


if __name__ == "__main__":
    unittest.main()
