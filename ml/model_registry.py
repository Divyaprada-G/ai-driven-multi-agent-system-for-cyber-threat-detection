"""
AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
Model Registry Persistence & Versioning
"""

import os
import json

ARTIFACTS_DIR = os.path.join(os.path.dirname(__file__), "artifacts")

def list_registered_models():
    """
    List all persisted model artifacts and their metadata.
    """
    models = []
    if not os.path.exists(ARTIFACTS_DIR):
        return models

    for entry in os.listdir(ARTIFACTS_DIR):
        dir_path = os.path.join(ARTIFACTS_DIR, entry)
        meta_file = os.path.join(dir_path, "metadata.json")
        if os.path.isdir(dir_path) and os.path.exists(meta_file):
            try:
                with open(meta_file, "r") as f:
                    meta = json.load(f)
                    models.append(meta)
            except Exception:
                continue
    return models

def get_model_metadata(model_id: str):
    """
    Retrieve metadata for a specific model ID.
    """
    meta_file = os.path.join(ARTIFACTS_DIR, model_id, "metadata.json")
    if not os.path.exists(meta_file):
        return None
    with open(meta_file, "r") as f:
        return json.load(f)
