"""
AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
Central Backend Configuration Module (Python FastAPI Backend)
"""

import os
from typing import List
from pydantic import BaseModel

class AppConfig(BaseModel):
    service_name: str = "cyber-threat-detection-ml-backend"
    version: str = "1.0.0"
    environment: str = os.getenv("NODE_ENV", "development")
    host: str = os.getenv("BACKEND_HOST", "127.0.0.1")
    port: int = int(os.getenv("BACKEND_PORT", "8000"))
    artifacts_dir: str = os.getenv("ML_ARTIFACTS_DIR", os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ml", "artifacts"))
    n8n_webhook_url: str = os.getenv("N8N_WEBHOOK_URL", "")
    allowed_cors_origins: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173"
    ]

config = AppConfig()
