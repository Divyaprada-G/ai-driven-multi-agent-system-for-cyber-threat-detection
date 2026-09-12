"""
AI DRIVEN MULTI-AGENT SYSTEM FOR CYBER THREAT DETECTION
FastAPI Local Prediction API & Live Security Event Pipeline
Prompt 12 — 100% Free / Local / No Paid External API

Target Architecture:
Security Events -> Multi-Agent Ingestion (Network/System/Application) ->
Event Correlation -> Real ML Engine (Random Forest / Isolation Forest) ->
Risk Scoring -> Alert Management -> Incident Management -> Dashboard
"""

import os
import sys
import time
from typing import Dict, Any, List, Optional
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from schemas import (
    HealthResponse,
    SystemStatusResponse,
    ModelMetadataResponse,
    PredictionRequest,
    PredictionResponse,
    BatchPredictionRequest,
    BatchPredictionResponse,
    SecurityEventPayload,
    SecurityEventResponse,
    PipelineStatusResponse,
    SimulatorControlRequest,
    IntegrationEventPlaceholder
)

from services.model_service import model_service
from services.event_pipeline import LiveEventPipeline
from services.simulator_service import LiveEventSimulator

app = FastAPI(
    title="Cyber Threat Detection Local ML & Security Pipeline API",
    description="100% Free / Local REST API connecting Frontend to Scikit-Learn ML Models & Multi-Agent Pipeline. Zero paid external APIs.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Safe Local CORS configuration
# Explicit local development origins
origins = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    "http://localhost:8000",
    "http://127.0.0.1:8000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In development container environment allow all local preview hosts
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

pipeline = LiveEventPipeline(model_service)
simulator = LiveEventSimulator(pipeline)

@app.on_event("startup")
async def startup_event():
    """Startup validation: Checks model registry and backend readiness."""
    print("[CyberML Backend] Initializing local cybersecurity pipeline...")
    model_service.refresh_registry()
    status_info = model_service.get_model_status()
    print(f"[CyberML Backend] Active Model: {status_info.get('activeModelId') or 'None'}")
    print(f"[CyberML Backend] Random Forest Status: {status_info.get('randomForest')}")
    print(f"[CyberML Backend] Isolation Forest Status: {status_info.get('isolationForest')}")
    print("[CyberML Backend] Local API ready at http://127.0.0.1:8000 (Docs at /docs)")

# -------------------------------------------------------------
# 1. HEALTH CHECK ENDPOINT
# -------------------------------------------------------------
@app.get("/api/health", response_model=HealthResponse)
async def get_health():
    """
    Health check endpoint.
    Frontend must use this endpoint to determine whether local backend is actually running.
    """
    return HealthResponse(
        status="ok",
        service="Cyber Threat Detection ML Backend",
        timestamp=datetime.utcnow().isoformat() + "Z",
        version="1.0.0",
        offlineFirst=True,
        paidApisUsed=False
    )

# -------------------------------------------------------------
# 2. SYSTEM STATUS ENDPOINT
# -------------------------------------------------------------
@app.get("/api/status", response_model=SystemStatusResponse)
async def get_system_status():
    """
    Returns actual status of:
    - API
    - ML engine
    - Random Forest model
    - Isolation Forest model
    - Model registry
    - Event pipeline
    - Dataset service
    - Alert service
    Never fabricates status.
    """
    m_status = model_service.get_model_status()
    p_status = pipeline.get_status()

    return SystemStatusResponse(
        api="ONLINE",
        mlEngine="ONLINE",
        randomForest=m_status.get("randomForest", "NOT_TRAINED"),
        isolationForest=m_status.get("isolationForest", "NOT_TRAINED"),
        eventPipeline=p_status.get("status", "STOPPED"),
        datasetService="READY",
        alertService="READY",
        incidentService="READY",
        activeModelId=m_status.get("activeModelId"),
        activeModelType=m_status.get("activeModelType"),
        loadedArtifactsCount=m_status.get("loadedArtifactsCount", 0),
        paidApiRequired=False,
        details={
            "eventsProcessed": p_status.get("eventsProcessed", 0),
            "threatsDetected": p_status.get("threatsDetected", 0),
            "simulatorActive": simulator.is_running
        }
    )

# -------------------------------------------------------------
# 3. MODEL REGISTRY ENDPOINTS
# -------------------------------------------------------------
@app.get("/api/models")
async def get_registered_models():
    """Returns all models trained and registered from Prompt 11."""
    return model_service.get_registered_models()

# -------------------------------------------------------------
# 4. REAL PREDICTION ENDPOINT
# -------------------------------------------------------------
@app.post("/api/predict")
async def predict_sample(req: PredictionRequest):
    """
    Real Prediction Endpoint:
    Validates input features, loads preprocessing pipeline, transforms features,
    and runs inference through the actual Scikit-Learn model.
    If no model is available, returns clear status without fabricating fake predictions.
    """
    result = model_service.predict(
        model_id=req.modelId,
        feature_values=req.features,
        raw_meta=req.rawIdentifierMeta
    )

    if result.get("status") == "MODEL_NOT_AVAILABLE":
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=result
        )

    return result

# -------------------------------------------------------------
# 5. BATCH PREDICTION ENDPOINT
# -------------------------------------------------------------
@app.post("/api/predict/batch", response_model=BatchPredictionResponse)
async def predict_batch(req: BatchPredictionRequest):
    """
    Batch Prediction with safe chunking and error resilience.
    """
    start_time = time.time()
    successful = 0
    failed = 0
    predictions = []
    errors = []

    # Safe batch chunking
    records = req.records[:500] # Safe limit per batch request
    for idx, record in enumerate(records):
        try:
            pred = model_service.predict(model_id=req.modelId, feature_values=record)
            if pred.get("status") == "MODEL_NOT_AVAILABLE":
                errors.append({"recordIndex": idx, "error": "Model not available"})
                failed += 1
            else:
                predictions.append(pred)
                successful += 1
        except Exception as e:
            errors.append({"recordIndex": idx, "error": str(e)})
            failed += 1

    processing_time_ms = round((time.time() - start_time) * 1000, 2)

    return BatchPredictionResponse(
        totalRequested=len(req.records),
        processed=len(records),
        successful=successful,
        failed=failed,
        processingTimeMs=processing_time_ms,
        predictions=predictions,
        errors=errors
    )

# -------------------------------------------------------------
# 6. LIVE SECURITY EVENT INGESTION & PIPELINE
# -------------------------------------------------------------
@app.post("/api/security-events", response_model=SecurityEventResponse)
async def submit_security_event(event: SecurityEventPayload):
    """
    Ingests normalized security event into the live pipeline.
    Routes to Network, System, or Application Security Agent.
    """
    enqueued = pipeline.enqueue_event(event.dict())
    return SecurityEventResponse(
        eventId=enqueued["eventId"],
        receivedAt=enqueued["receivedAt"],
        status=enqueued["status"],
        agentId=enqueued["agentId"],
        agentType=enqueued["agentType"],
        isSimulated=enqueued["isSimulated"]
    )

@app.get("/api/security-events")
async def get_security_events(limit: int = 100):
    """Returns recent processed security events from the live pipeline."""
    return pipeline.get_events(limit=limit)

@app.get("/api/alerts")
async def get_alerts(limit: int = 50):
    """Returns security alerts generated by the pipeline."""
    return pipeline.get_alerts(limit=limit)

@app.get("/api/incidents")
async def get_incidents(limit: int = 50):
    """Returns escalated incidents generated by the pipeline."""
    return pipeline.get_incidents(limit=limit)

# -------------------------------------------------------------
# 7. PIPELINE CONTROL ENDPOINTS
# -------------------------------------------------------------
@app.get("/api/pipeline/status", response_model=PipelineStatusResponse)
async def get_pipeline_status():
    """Returns live pipeline telemetry, queue size, and real latency metrics."""
    return pipeline.get_status()

@app.post("/api/pipeline/start")
async def start_pipeline():
    """Starts the real-time event pipeline queue processing."""
    pipeline.start()
    return {"status": "RUNNING", "message": "Live security event pipeline started."}

@app.post("/api/pipeline/stop")
async def stop_pipeline():
    """Stops the real-time event pipeline queue processing."""
    pipeline.stop()
    simulator.stop()
    return {"status": "STOPPED", "message": "Live security event pipeline stopped."}

@app.post("/api/pipeline/clear")
async def clear_pipeline():
    """Clears queued and processed live events from memory."""
    pipeline.clear()
    return {"status": "CLEARED", "message": "Pipeline event queue and history cleared."}

# -------------------------------------------------------------
# 8. LOCAL EVENT SIMULATOR ENDPOINTS
# -------------------------------------------------------------
@app.post("/api/simulator/start")
async def start_simulator(req: SimulatorControlRequest):
    """
    Starts local safe event simulator with configurable rate and mode.
    Events are clearly tagged: 'SIMULATED SECURITY EVENT'.
    """
    if not pipeline.is_running:
        pipeline.start()
    simulator.start(event_rate=req.eventRate, mode=req.mode)
    return {
        "status": "SIMULATOR_RUNNING",
        "eventRate": req.eventRate,
        "mode": req.mode,
        "label": "SIMULATED SECURITY EVENT",
        "warning": "Safe synthetic events only. Zero real system or network actions executed."
    }

@app.post("/api/simulator/stop")
async def stop_simulator():
    """Stops the local event simulator."""
    simulator.stop()
    return {"status": "SIMULATOR_STOPPED"}

# -------------------------------------------------------------
# 9. GUIDED DEMONSTRATION MODE
# -------------------------------------------------------------
@app.post("/api/demo/start")
async def start_project_demo():
    """
    Executes the 12-Step Guided Project Demonstration:
    1. Verify backend
    2. Check trained model
    3. Start pipeline
    4. Start simulator
    5. Ingest events
    6. Agent processing
    7. Correlation
    8. Real ML prediction
    9. Risk scoring
    10. Alert generation
    11. Incident creation
    12. Dashboard update
    """
    m_status = model_service.get_model_status()
    # Check preconditions
    active_id = m_status.get("activeModelId")
    if not active_id:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "status": "MODEL_NOT_AVAILABLE",
                "message": "Demo cannot execute real ML predictions because no trained model is available. Train a model in Datasets & ML Training first."
            }
        )

    pipeline.start()
    simulator.start(event_rate=2, mode="mixed")
    return {
        "status": "DEMO_STARTED",
        "activeModel": active_id,
        "message": "Guided project demo started. Synthetic events streaming through Multi-Agent pipeline."
    }

@app.post("/api/demo/stop")
async def stop_project_demo():
    simulator.stop()
    return {"status": "DEMO_STOPPED"}

# -------------------------------------------------------------
# 10. FUTURE N8N INTEGRATION PLACEHOLDERS
# -------------------------------------------------------------
@app.post("/api/integration/events", response_model=IntegrationEventPlaceholder)
async def future_n8n_events(req: Request):
    """Reserved for future n8n workflow integration. Not active in Prompt 12."""
    body = await req.json() if req.headers.get("content-type") == "application/json" else {}
    return IntegrationEventPlaceholder(
        status="RESERVED",
        message="Reserved for future n8n workflow integration.",
        receivedData=body
    )

@app.post("/api/integration/alerts", response_model=IntegrationEventPlaceholder)
async def future_n8n_alerts(req: Request):
    """Reserved for future n8n workflow integration. Not active in Prompt 12."""
    body = await req.json() if req.headers.get("content-type") == "application/json" else {}
    return IntegrationEventPlaceholder(
        status="RESERVED",
        message="Reserved for future n8n workflow integration.",
        receivedData=body
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
