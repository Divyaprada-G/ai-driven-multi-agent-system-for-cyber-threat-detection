import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient
from main import app
from services.model_service import model_service

class TestMLEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_01_core_library_imports(self):
        """Verify Python environment can import all required ML libraries."""
        import fastapi
        import sklearn
        import joblib
        import pandas
        import numpy
        self.assertIsNotNone(fastapi.__version__)
        self.assertIsNotNone(sklearn.__version__)
        self.assertIsNotNone(joblib.__version__)
        self.assertIsNotNone(pandas.__version__)
        self.assertIsNotNone(numpy.__version__)

    def test_02_ml_health_endpoint(self):
        """Verify GET /api/ml/health returns valid status."""
        response = self.client.get("/api/ml/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("status", data)
        self.assertIn("framework", data)
        self.assertEqual(data["framework"], "scikit-learn")
        self.assertTrue(data["scikitLearnAvailable"])

    def test_03_ml_model_status_endpoint(self):
        """Verify GET /api/ml/model-status returns detailed status without fake claims."""
        response = self.client.get("/api/ml/model-status")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("status", data)
        self.assertIn(data["status"], ["MODEL_READY", "ARTIFACTS_MISSING", "MODEL_LOADING", "MODEL_ERROR"])
        self.assertIn("randomForest", data)
        self.assertIn("isolationForest", data)
        self.assertIn("loadedArtifactsCount", data)

    def test_04_ml_models_registry(self):
        """Verify registered model artifacts and metadata."""
        response = self.client.get("/api/ml/models")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)
        first_model = data[0]
        self.assertTrue("modelId" in first_model or "model_id" in first_model)
        self.assertTrue("modelType" in first_model or "model_type" in first_model)

    def test_05_ml_predict_real_inference(self):
        """Verify POST /api/ml/predict performs real inference and includes all required fields."""
        sample_features = {
            "Flow Duration": 500,
            "Total Fwd Packets": 2,
            "Total Backward Packets": 1,
            "SYN Flag Count": 1
        }
        response = self.client.post("/api/ml/predict", json={
            "features": sample_features
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        # Requirement 6: predicted class, probabilities/confidence, model version, anomaly score
        self.assertIn("predictedClass", data)
        self.assertIn("confidence", data)
        self.assertIn("modelVersion", data)
        self.assertIn("classProbabilities", data)
        self.assertIsInstance(data["confidence"], float)
        self.assertIn("anomalyScore", data)
        self.assertIn("anomalyFlag", data)

    def test_06_ml_predict_invalid_payload_handling(self):
        """Verify invalid payload returns HTTP 400 with helpful error, not 500 crash."""
        # Empty features
        resp_empty = self.client.post("/api/ml/predict", json={"features": {}})
        self.assertEqual(resp_empty.status_code, 400)
        self.assertIn("detail", resp_empty.json())

        # Non-numeric feature value
        resp_bad = self.client.post("/api/ml/predict", json={
            "features": {"Flow Duration": "NOT_A_NUMBER_STRING"}
        })
        self.assertEqual(resp_bad.status_code, 400)
        self.assertIn("numeric", resp_bad.json()["detail"])

    def test_07_ml_predict_batch(self):
        """Verify batch inference execution."""
        records = [
            {"Flow Duration": 100, "Total Fwd Packets": 1},
            {"Flow Duration": 1000000, "Total Fwd Packets": 50, "SYN Flag Count": 10}
        ]
        response = self.client.post("/api/ml/predict/batch", json={
            "records": records
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["totalProcessed"], 2)
        self.assertEqual(len(data["predictions"]), 2)

if __name__ == "__main__":
    unittest.main()
