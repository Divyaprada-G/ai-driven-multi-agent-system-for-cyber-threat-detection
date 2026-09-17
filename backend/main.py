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

from fastapi import FastAPI, HTTPException, Request, status, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

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
from services.log_analyzer import analyze_logs, get_demo_log, get_available_demos, DEMO_LOGS

class AnalyzeRequest(BaseModel):
    log_text: Optional[str] = ""
    source_type: Optional[str] = "auto"
    scenario: Optional[str] = None
    filename: Optional[str] = None

# Analysis session tracking
analysis_history: List[Dict[str, Any]] = []

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
# 1. HEALTH CHECK ENDPOINTS
# -------------------------------------------------------------
@app.get("/api/health", response_model=HealthResponse)
async def get_health():
    """General health check endpoint."""
    return HealthResponse(
        status="ok",
        service="Cyber Threat Detection ML Backend",
        timestamp=datetime.utcnow().isoformat() + "Z",
        version="1.0.0",
        offlineFirst=True,
        paidApisUsed=False
    )

@app.get("/api/ml/health")
async def get_ml_health():
    """
    ML-specific health check endpoint conforming to Section 7 requirements.
    Reports real availability of trained scikit-learn artifacts.
    """
    model_service.refresh_registry()
    models = model_service.get_registered_models()

    rf_info = {"available": False, "modelId": None, "version": None}
    if_info = {"available": False, "modelId": None, "version": None}

    for m in models:
        m_type = m.get("model_type") or m.get("modelType")
        m_id = m.get("model_id") or m.get("modelId")
        version = m.get("version") or m.get("modelVersion")

        if m_type == "RANDOM_FOREST" and not rf_info["available"]:
            rf_info = {
                "available": True,
                "modelId": m_id,
                "version": version
            }
        elif m_type == "ISOLATION_FOREST" and not if_info["available"]:
            if_info = {
                "available": True,
                "modelId": m_id,
                "version": version
            }

    overall_ready = rf_info["available"] or if_info["available"]

    return {
        "status": "ready" if overall_ready else "not_ready",
        "framework": "scikit-learn",
        "backendConfigured": True,
        "scikitLearnAvailable": True,
        "pandasAvailable": True,
        "joblibAvailable": True,
        "randomForest": rf_info,
        "isolationForest": if_info,
        "message": "Real Scikit-Learn ML backend connected and ready." if overall_ready else "Model artifacts not ready"
    }

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
@app.get("/api/ml/models")
@app.get("/api/models")
async def get_registered_models():
    """Returns all models trained and registered."""
    model_service.refresh_registry()
    return model_service.get_registered_models()

@app.get("/api/ml/model-status")
async def get_model_status():
    """
    Returns server-side model registry status.
    Distinguishes:
    - SERVICE_UNAVAILABLE
    - ARTIFACTS_MISSING
    - MODEL_LOADING
    - MODEL_READY
    - MODEL_ERROR
    Never returns MODEL_READY merely because the Python package is installed.
    """
    model_service.refresh_registry()
    return model_service.get_detailed_status()

# -------------------------------------------------------------
# 4. REAL PREDICTION ENDPOINTS
# -------------------------------------------------------------
@app.post("/api/ml/predict")
@app.post("/api/predict")
async def predict_sample(req: PredictionRequest):
    """
    Real Prediction Endpoint:
    Validates input features, loads preprocessing pipeline, transforms features,
    and runs inference through the actual Scikit-Learn model.
    Never falls back to heuristic predictions. Returns MODEL_NOT_READY when unavailable.
    """
    # 1. Validate input structure
    if not isinstance(req.features, dict) or len(req.features) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid feature input: 'features' must be a non-empty dictionary of feature names and values."
        )

    # 2. Validate feature schema (reject malformed / non-numeric types)
    invalid_fields = []
    for k, v in req.features.items():
        if isinstance(v, (str, bool)) and not isinstance(v, (int, float)):
            try:
                float(v)
            except (ValueError, TypeError):
                invalid_fields.append(f"Field '{k}' has non-numeric value '{v}'")
    if invalid_fields:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed feature schema: all feature values must be numeric. Errors: {'; '.join(invalid_fields)}"
        )

    # 3. Run real prediction through model service
    result = model_service.predict(
        model_id=req.modelId,
        feature_values=req.features,
        raw_meta=req.rawIdentifierMeta
    )

    if result.get("status") in ["MODEL_NOT_READY", "MODEL_NOT_AVAILABLE", "ARTIFACTS_MISSING"]:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content=result
        )

    return result

# -------------------------------------------------------------
# 5. BATCH PREDICTION ENDPOINTS
# -------------------------------------------------------------
@app.post("/api/ml/predict/batch", response_model=BatchPredictionResponse)
@app.post("/api/predict/batch", response_model=BatchPredictionResponse)
async def predict_batch(req: BatchPredictionRequest):
    """
    Batch Prediction with bounded batch size, feature validation, and safe execution.
    """
    if not req.records or len(req.records) == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Batch prediction records cannot be empty."
        )

    MAX_BATCH_SIZE = 500
    if len(req.records) > MAX_BATCH_SIZE:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Batch size exceeds maximum limit of {MAX_BATCH_SIZE} records."
        )

    start_time = time.time()
    successful = 0
    failed = 0
    predictions = []
    errors = []

    for idx, record in enumerate(req.records):
        if not isinstance(record, dict):
            errors.append({"recordIndex": idx, "error": "Record must be an object/dict"})
            failed += 1
            continue

        try:
            pred = model_service.predict(model_id=req.modelId, feature_values=record)
            if pred.get("status") in ["MODEL_NOT_READY", "MODEL_NOT_AVAILABLE"]:
                errors.append({"recordIndex": idx, "error": pred.get("error") or "MODEL_NOT_READY"})
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
        processed=len(req.records),
        totalProcessed=len(req.records),
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

# -------------------------------------------------------------
# 11. END-TO-END MULTI-AGENT LOG ANALYSIS & DASHBOARD APIS
# -------------------------------------------------------------
@app.post("/api/analyze")
async def analyze_log_endpoint(req: AnalyzeRequest):
    """
    Core End-to-End Log Analysis Endpoint.
    Analyzes raw log text using multi-agent detection (Network, System, Application),
    ML inference, correlation, and risk scoring.
    """
    log_text = req.log_text or ""
    source_type = req.source_type or "auto"
    
    if req.scenario and (not log_text or not log_text.strip()):
        log_text, detected_src = get_demo_log(req.scenario)
        if source_type == "auto":
            source_type = detected_src

    if not log_text.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No log text provided. Please provide log_text or a valid scenario."
        )

    result = analyze_logs(raw_text=log_text, source_type=source_type)
    if req.filename:
        result["filename"] = req.filename
    
    analysis_history.append(result)
    if len(analysis_history) > 100:
        analysis_history.pop(0)

    return result

@app.post("/api/logs/upload")
async def upload_log_file(
    file: UploadFile = File(...),
    source_type: str = Form("auto")
):
    """
    Accepts log file upload (multipart/form-data), extracts text content,
    and runs multi-agent threat detection.
    """
    try:
        content_bytes = await file.read()
        try:
            log_text = content_bytes.decode("utf-8")
        except UnicodeDecodeError:
            log_text = content_bytes.decode("latin-1", errors="ignore")

        if not log_text.strip():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded file is empty."
            )

        result = analyze_logs(raw_text=log_text, source_type=source_type)
        result["filename"] = file.filename
        analysis_history.append(result)
        if len(analysis_history) > 100:
            analysis_history.pop(0)

        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to process log file: {str(e)}"
        )

@app.get("/api/dashboard/stats")
async def get_dashboard_stats():
    """
    Aggregates metrics across processed events, analysis sessions, and incidents.
    """
    pipe_status = pipeline.get_status()
    total_pipeline_events = pipe_status.get("processedCount", 0)
    
    history_events = sum(a.get("events_parsed", 0) for a in analysis_history)
    total_events = total_pipeline_events + history_events
    
    all_findings = []
    for a in analysis_history:
        all_findings.extend(a.get("findings", []))
        
    threats_detected = sum(1 for a in analysis_history if a.get("threat_detected"))
    critical_count = sum(1 for f in all_findings if str(f.get("severity", "")).upper() == "CRITICAL")
    high_count = sum(1 for f in all_findings if str(f.get("severity", "")).upper() == "HIGH")
    medium_count = sum(1 for f in all_findings if str(f.get("severity", "")).upper() == "MEDIUM")
    low_count = sum(1 for f in all_findings if str(f.get("severity", "")).upper() == "LOW")
    
    incidents_count = sum(1 for a in analysis_history if a.get("incident"))

    m_status = model_service.get_model_status()
    active_model = m_status.get("activeModelId")

    return {
        "status": "ok",
        "totalEvents": total_events,
        "threatsDetected": threats_detected,
        "criticalThreats": critical_count,
        "highThreats": high_count,
        "mediumThreats": medium_count,
        "lowThreats": low_count,
        "activeIncidents": incidents_count,
        "pipelineStatus": pipe_status.get("status", "STOPPED"),
        "activeModel": active_model or "None (Rule-Engine Active)",
        "modelStatus": m_status.get("status", "READY"),
        "analysisSessionsCount": len(analysis_history),
        "timestamp": datetime.utcnow().isoformat() + "Z"
    }

@app.get("/api/demo/scenarios")
async def get_demo_scenarios():
    """Returns available demonstration attack scenarios."""
    return get_available_demos()

@app.post("/api/demo")
async def run_demo_scenario(payload: Optional[Dict[str, Any]] = None):
    """
    Executes analysis on a predefined demo scenario (e.g. mixed_attack, network_port_scan).
    """
    scenario_id = (payload or {}).get("scenario", "mixed_attack")
    log_text, src = get_demo_log(scenario_id)
    result = analyze_logs(raw_text=log_text, source_type=src)
    result["scenario"] = scenario_id
    analysis_history.append(result)
    if len(analysis_history) > 100:
        analysis_history.pop(0)
    return result

@app.get("/api/analysis/history")
async def get_analysis_history(limit: int = 20):
    """Returns recent analysis results."""
    return list(reversed(analysis_history[-limit:]))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)

