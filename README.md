# CyberSpendAI FastAPI Backend (Render-ready)

Deployable prototype API for risk analysis, illustrative FAIR-inspired loss quantification, Monte Carlo loss estimates, what-if scenarios, security investment optimization, and ingestion-envelope validation.

## Local run

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload
```

Open `http://127.0.0.1:8000/docs` for interactive API docs.

## Render deployment

1. Upload this folder to a GitHub repository (the `main.py`, `requirements.txt`, and `render.yaml` must be at repository root).
2. In Render, choose **New + → Blueprint** and select the repository; Render reads `render.yaml`. Or create a **Web Service** with:
   - Runtime: Python 3
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - Health check path: `/health`
3. After deployment, test `https://YOUR-SERVICE.onrender.com/health` and `https://YOUR-SERVICE.onrender.com/docs`.
4. Set `FRONTEND_ORIGINS` to the exact comma-separated frontend origins that need CORS access.

## Main endpoints

- `GET /` and `GET /health`
- `GET /api/v1`
- `POST /api/v1/risk/analyze` — multi-asset risk metrics + illustrative Monte Carlo VaR
- `POST /api/v1/risk/what-if` — scenario analysis
- `POST /api/v1/optimizer/run` — budget-based greedy investment recommendation
- `POST /api/v1/data/ingest` — validates an ingestion envelope (does not persist)
- `GET /api/v1/metrics/summary`
- Compatibility aliases: `POST /risk/analyze`, `POST /optimizer/run`

## Sample risk request

```json
{
  "assets": [
    {
      "asset_id": "B-001",
      "asset_name": "Internet Banking Portal",
      "asset_category": "Application",
      "business_unit": "Digital Banking",
      "asset_value_inr": 20000000,
      "criticality": "Critical",
      "internet_exposed": true,
      "threat_type": "External cyber attack",
      "vulnerability": "Web application vulnerability",
      "cvss_score": 9.8,
      "known_exploited": true,
      "annual_threat_event_frequency": 3,
      "vulnerability_probability": 0.4,
      "primary_loss_inr": 2500000,
      "secondary_loss_inr": 1000000,
      "control_effectiveness": 0.2,
      "uncertainty_factor": 1.8,
      "data_sensitivity": "Very High"
    }
  ],
  "confidence_level": 0.95,
  "simulations": 3000,
  "seed": 42
}
```

## Sample optimizer request

```json
{
  "budget_inr": 1000000,
  "baseline_annual_loss_inr": 5000000,
  "controls": [
    {"control_id":"MFA-01","name":"Privileged MFA","cost_inr":250000,"risk_reduction":0.18,"implementation_months":1,"category":"Identity"},
    {"control_id":"EDR-01","name":"Endpoint detection rollout","cost_inr":500000,"risk_reduction":0.25,"implementation_months":2,"category":"Detection"},
    {"control_id":"WAF-01","name":"Web application firewall tuning","cost_inr":300000,"risk_reduction":0.15,"implementation_months":1,"category":"Preventive"}
  ]
}
```

## Important prototype limitations

- The risk logic is **FAIR-inspired**, not a certified/complete FAIR implementation. Frequency, vulnerability probability, loss magnitudes, and uncertainty assumptions must be calibrated with organization-specific data.
- VaR is an illustrative Monte Carlo estimate, not a regulatory or actuarial forecast.
- Optimizer uses a transparent greedy heuristic, not a guaranteed globally optimal solver.
- Ingestion endpoint validates request structure only; it does not connect to SIEM/EDR APIs or persist records.
- No database, authentication, tenancy, or secrets integration is configured. Do not send sensitive real organization data until those are implemented.
