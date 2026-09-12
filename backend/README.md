# Local Real-Time Prediction API & Live Security Pipeline
**100% Free / Local / No Paid External API**

## Target Architecture
```
                  SECURITY EVENTS
                        │
             ┌──────────┼──────────┐
             ↓          ↓          ↓
        Network      System    Application
         Logs         Logs        Logs
             ↓          ↓          ↓
       Network       System    Application
        Agent         Agent       Agent
             └──────────┼──────────┘
                        ↓
               EVENT CORRELATION
                        ↓
                REAL ML ENGINE
                 ┌──────┴──────┐
                 ↓             ↓
          Random Forest   Isolation Forest
                 └──────┬──────┘
                        ↓
                THREAT DETECTION
                        ↓
                  RISK SCORING
                        ↓
                 ALERT MANAGER
                        ↓
               INCIDENT MANAGER
                        ↓
                   DASHBOARD
```

## Local Startup Instructions

### 1. Prerequisites
- Python 3.10+
- No external API key required
- No cloud account or paid subscription required

### 2. Create Virtual Environment
```bash
python -m venv .venv
```

**Activate Environment:**
- **Linux/macOS:**
  ```bash
  source .venv/bin/activate
  ```
- **Windows:**
  ```cmd
  .venv\Scripts\activate
  ```

### 3. Install Local Dependencies
```bash
pip install -r backend/requirements.txt
```

### 4. Start the Local API Server
```bash
cd backend
uvicorn main:app --reload --port 8000
```
- API will listen at: `http://127.0.0.1:8000`
- Interactive OpenAPI / Swagger UI: `http://127.0.0.1:8000/docs`

### 5. Run Test Suite
```bash
python -m unittest backend/tests/test_api.py
```

### Endpoints
- `GET /api/health`: Health status
- `GET /api/status`: System, ML, and Pipeline status
- `GET /api/models`: Model registry metadata
- `POST /api/predict`: Scikit-learn inference with explainability
- `POST /api/predict/batch`: Safe batch inference
- `POST /api/security-events`: Normalized event ingestion & agent routing
- `GET /api/security-events`: Live event stream
- `GET /api/alerts`: Active alerts
- `GET /api/incidents`: Active incidents
- `GET /api/pipeline/status`: Real latency & processing statistics
- `POST /api/pipeline/start`: Start event processing queue
- `POST /api/pipeline/stop`: Stop event processing queue
- `POST /api/simulator/start`: Start synthetic event generator
- `POST /api/simulator/stop`: Stop synthetic event generator
- `POST /api/demo/start`: One-click guided 12-step demonstration
