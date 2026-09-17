#!/usr/bin/env python3
"""
CLI Prediction Script for AI-Driven Multi-Agent Cyber Threat Detection
Runs inference using registered Random Forest or Isolation Forest models.

Usage:
  python3 ml/predict.py --features '{"Destination Port": 22, "Flow Packets/s": 800}' [--model-id MODEL_ID]
"""
import sys
import os
import argparse
import json

current_dir = os.path.dirname(os.path.abspath(__file__))
root_dir = os.path.dirname(current_dir)
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)

from cyber_agents.ml_pipeline import MLPipeline


def main():
    parser = argparse.ArgumentParser(description="Run Threat Detection Inference")
    parser.add_argument("--features", type=str, required=True, help="JSON string of feature key-value pairs")
    parser.add_argument("--model-id", type=str, default=None, help="Model ID (optional, defaults to active model)")

    args = parser.parse_args()

    try:
        features = json.loads(args.features)
    except json.JSONDecodeError as e:
        print(f"Error parsing JSON features: {e}")
        sys.exit(1)

    pipeline = MLPipeline()
    try:
        result = pipeline.predict_sample(features=features, model_id=args.model_id)
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Prediction failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
