"""
AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
Unit & Integration Tests for Local API & Pipeline (Prompt 12)
"""

import sys
import os
import unittest
from unittest.mock import MagicMock

# Add backend directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.model_service import ModelService
from services.event_pipeline import LiveEventPipeline
from services.simulator_service import LiveEventSimulator

class TestCyberThreatBackend(unittest.TestCase):
    def setUp(self):
        self.mock_model_service = MagicMock(spec=ModelService)
        self.mock_model_service.predict.return_value = {
            "predictionId": "PRED-TEST-001",
            "modelId": "RF-TEST-01",
            "modelVersion": "v1.0",
            "modelStatus": "TRAINED",
            "predictedClass": "DDoS",
            "confidence": 0.94,
            "confidenceDisclaimer": "Test disclaimer",
            "status": "COMPLETED"
        }
        self.mock_model_service.get_model_status.return_value = {
            "randomForest": "TRAINED",
            "isolationForest": "TRAINED",
            "activeModelId": "RF-TEST-01",
            "activeModelType": "RANDOM_FOREST",
            "loadedArtifactsCount": 1
        }
        self.pipeline = LiveEventPipeline(self.mock_model_service)

    def test_multi_agent_routing_network(self):
        """Test Network event routes to Network Security Agent"""
        event = {
            "source": "network",
            "eventType": "SYN Flood Probe",
            "features": {"Flow Duration": 100000}
        }
        queued = self.pipeline.enqueue_event(event)
        self.assertEqual(queued["agentId"], "agent-network-1")
        self.assertEqual(queued["agentType"], "Network Security Agent")
        self.assertTrue(queued["isSimulated"])

    def test_multi_agent_routing_system(self):
        """Test System event routes to System Security Agent"""
        event = {
            "source": "system",
            "eventType": "Repeated sudo failure",
            "features": {"failedLoginsCount": 5}
        }
        queued = self.pipeline.enqueue_event(event)
        self.assertEqual(queued["agentId"], "agent-system-1")
        self.assertEqual(queued["agentType"], "System Security Agent")

    def test_multi_agent_routing_application(self):
        """Test Application event routes to Application Security Agent"""
        event = {
            "source": "application",
            "eventType": "SQLi attempt",
            "features": {"payloadRiskKeywords": 2}
        }
        queued = self.pipeline.enqueue_event(event)
        self.assertEqual(queued["agentId"], "agent-app-1")
        self.assertEqual(queued["agentType"], "Application Security Agent")

    def test_id_lineage_preservation(self):
        """Test end-to-end ID preservation across all pipeline stages"""
        event = {
            "eventId": "EVT-TEST-12345",
            "source": "network",
            "eventType": "DDoS flood",
            "features": {"Flow Duration": 5000000}
        }
        item = self.pipeline.enqueue_event(event)
        self.pipeline._process_single_event(item)

        events = self.pipeline.get_events()
        self.assertEqual(len(events), 1)
        proc = events[0]
        
        # Verify full lineage is populated
        self.assertEqual(proc["eventId"], "EVT-TEST-12345")
        self.assertTrue(proc["findingId"].startswith("FIND-"))
        self.assertTrue(proc["correlationId"].startswith("CORR-"))
        self.assertTrue(proc["threatDetectionId"].startswith("THREAT-"))
        self.assertTrue(proc["riskAssessmentId"].startswith("RISK-"))
        self.assertTrue(proc["alertId"].startswith("ALT-"))
        self.assertIsNotNone(proc["incidentId"])
        self.assertGreater(proc["latencyMs"], 0.0)

    def test_simulated_event_marking(self):
        """Test simulated events are ALWAYS marked with isSimulated=True"""
        sim = LiveEventSimulator(self.pipeline)
        synth_event = sim._generate_synthetic_event(0)
        self.assertTrue(synth_event["isSimulated"])
        self.assertIn("[SIMULATED]", synth_event["eventType"])

    def test_no_trained_model_handling(self):
        """Test when no model is available, pipeline returns MODEL_NOT_AVAILABLE without fake data"""
        real_model_service = ModelService(artifacts_dir="/tmp/non_existent_artifacts")
        status = real_model_service.get_model_status()
        self.assertEqual(status["randomForest"], "NOT_TRAINED")
        self.assertIsNone(status["activeModelId"])

        pred = real_model_service.predict(None, {"Flow Duration": 100})
        self.assertEqual(pred["status"], "MODEL_NOT_AVAILABLE")

if __name__ == "__main__":
    unittest.main()
