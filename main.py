from __future__ import annotations

import math
import os
import random
from datetime import datetime, timezone
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, ConfigDict

APP_VERSION = "1.0.0"

app = FastAPI(
    title="CyberSpendAI Risk Intelligence API",
    description=(
        "Deployable prototype API for cyber-risk quantification, FAIR-inspired loss "
        "analysis, what-if simulations, and security investment optimization. "
        "Outputs are decision-support estimates, not actuarial guarantees."
    ),
    version=APP_VERSION,
)

# Configure FRONTEND_ORIGINS on Render as comma-separated origins if needed.
_origins = os.getenv(
    "FRONTEND_ORIGINS",
    "https://cyber-spend-ai-sih-project-code-hus.vercel.app,http://localhost:3000,http://localhost:5173",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[x.strip() for x in _origins.split(",") if x.strip()],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

INR = "INR"

class AssetRiskInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True)
    asset_id: str = Field(default="ASSET-001", min_length=1, max_length=100)
    asset_name: str = Field(default="Internet Banking Portal", min_length=1, max_length=200)
    asset_category: str = Field(default="Application", max_length=100)
    business_unit: str = Field(default="Digital Banking", max_length=100)
    asset_value_inr: float = Field(default=20_000_000, gt=0)
    criticality: Literal["Low", "Medium", "High", "Critical"] = "High"
    internet_exposed: bool = True
    threat_type: str = Field(default="External cyber attack", max_length=200)
    vulnerability: str = Field(default="Web application vulnerability", max_length=300)
    cvss_score: float = Field(default=8.1, ge=0, le=10)
    known_exploited: bool = False
    annual_threat_event_frequency: float = Field(default=2.0, ge=0, le=10000, description="Estimated threat events per year")
    vulnerability_probability: float = Field(default=0.35, ge=0, le=1, description="Probability a threat event successfully exploits the weakness")
    primary_loss_inr: float = Field(default=1_500_000, ge=0)
    secondary_loss_inr: float = Field(default=500_000, ge=0)
    control_effectiveness: float = Field(default=0.25, ge=0, le=1)
    uncertainty_factor: float = Field(default=1.5, ge=1, le=10, description="Multiplicative uncertainty range used for illustrative VaR estimate")
    data_sensitivity: Literal["Low", "Moderate", "High", "Very High"] = "High"
    tags: list[str] = Field(default_factory=list, max_length=30)

class RiskAnalyzeRequest(BaseModel):
    assets: list[AssetRiskInput] = Field(min_length=1, max_length=500)
    confidence_level: float = Field(default=0.95, gt=0.5, lt=0.999)
    simulations: int = Field(default=5000, ge=100, le=50000)
    seed: int = Field(default=42, ge=0, le=2**32 - 1)

class WhatIfRequest(BaseModel):
    asset: AssetRiskInput
    control_effectiveness_delta: float = Field(default=0.2, ge=0, le=1)
    threat_frequency_multiplier: float = Field(default=1.0, ge=0, le=10)
    loss_magnitude_multiplier: float = Field(default=1.0, ge=0, le=10)

class ControlOption(BaseModel):
    control_id: str = Field(min_length=1, max_length=100)
    name: str = Field(min_length=1, max_length=200)
    cost_inr: float = Field(gt=0)
    risk_reduction: float = Field(gt=0, le=1, description="Estimated proportional reduction in annual loss")
    implementation_months: int = Field(default=3, ge=0, le=120)
    category: str = Field(default="Preventive", max_length=100)

class OptimizerRequest(BaseModel):
    budget_inr: float = Field(ge=0)
    baseline_annual_loss_inr: float = Field(ge=0)
    controls: list[ControlOption] = Field(min_length=1, max_length=200)
    method: Literal["greedy_roi"] = "greedy_roi"

class IngestRequest(BaseModel):
    source: Literal["manual", "siem", "edr", "iam", "cspm", "vulnerability_scanner", "asset_inventory", "threat_intel"] = "manual"
    records: list[dict] = Field(min_length=1, max_length=1000)


def severity_band(score: float) -> str:
    if score >= 9: return "Critical"
    if score >= 7: return "High"
    if score >= 4: return "Medium"
    return "Low"


def risk_score(asset: AssetRiskInput) -> float:
    score = asset.cvss_score
    score += 0.8 if asset.internet_exposed else 0
    score += 0.8 if asset.known_exploited else 0
    score += {"Low": -0.8, "Medium": 0, "High": 0.6, "Critical": 1.0}[asset.criticality]
    score += {"Low": -0.4, "Moderate": 0, "High": 0.3, "Very High": 0.6}[asset.data_sensitivity]
    return round(max(0, min(10, score)), 2)


def calculate_asset(asset: AssetRiskInput) -> dict:
    exposure_rate = asset.annual_threat_event_frequency * asset.vulnerability_probability
    gross_loss_per_event = asset.primary_loss_inr + asset.secondary_loss_inr
    baseline_eal = exposure_rate * gross_loss_per_event
    residual_eal = baseline_eal * (1 - asset.control_effectiveness)
    avoided_loss = baseline_eal - residual_eal
    score = risk_score(asset)
    # Simple transparent approximation, not a full calibrated FAIR distribution.
    var_estimate = residual_eal * asset.uncertainty_factor
    return {
        "asset_id": asset.asset_id,
        "asset_name": asset.asset_name,
        "business_unit": asset.business_unit,
        "asset_category": asset.asset_category,
        "risk_score": score,
        "risk_level": severity_band(score),
        "annualized_loss_exposure_inr": round(baseline_eal, 2),
        "residual_annual_loss_inr": round(residual_eal, 2),
        "estimated_annual_loss_reduction_inr": round(avoided_loss, 2),
        "estimated_var_inr": round(var_estimate, 2),
        "threat_event_frequency_per_year": asset.annual_threat_event_frequency,
        "vulnerability_probability": asset.vulnerability_probability,
        "control_effectiveness": asset.control_effectiveness,
        "risk_drivers": [
            label for condition, label in [
                (asset.internet_exposed, "Internet exposed"),
                (asset.known_exploited, "Known exploited vulnerability"),
                (asset.cvss_score >= 7, "High CVSS severity"),
                (asset.criticality in ("High", "Critical"), "High business criticality"),
            ] if condition
        ],
        "currency": INR,
    }


def percentile(values: list[float], q: float) -> float:
    if not values: return 0.0
    ordered = sorted(values)
    pos = (len(ordered) - 1) * q
    lo = math.floor(pos); hi = math.ceil(pos)
    if lo == hi: return ordered[lo]
    return ordered[lo] * (hi - pos) + ordered[hi] * (pos - lo)


def simulate_portfolio(assets: list[AssetRiskInput], simulations: int, seed: int, confidence: float) -> dict:
    rng = random.Random(seed)
    annual_losses: list[float] = []
    for _ in range(simulations):
        total = 0.0
        for a in assets:
            frequency = a.annual_threat_event_frequency * a.vulnerability_probability
            # Poisson count by product of independent event probability and frequency;
            # cap at 50 to keep extreme input values computationally bounded.
            count = min(50, int(rng.gauss(frequency, math.sqrt(max(frequency, 0.01))) + 0.5))
            count = max(0, count)
            for _event in range(count):
                base = a.primary_loss_inr + a.secondary_loss_inr
                uncertainty = rng.uniform(1 / a.uncertainty_factor, a.uncertainty_factor)
                total += base * uncertainty * (1 - a.control_effectiveness)
        annual_losses.append(total)
    return {
        "simulation_count": simulations,
        "confidence_level": confidence,
        "simulated_mean_annual_loss_inr": round(sum(annual_losses) / len(annual_losses), 2),
        "var_inr": round(percentile(annual_losses, confidence), 2),
        "median_annual_loss_inr": round(percentile(annual_losses, 0.5), 2),
        "p95_annual_loss_inr": round(percentile(annual_losses, 0.95), 2),
        "p99_annual_loss_inr": round(percentile(annual_losses, 0.99), 2),
        "method_note": "Illustrative Monte Carlo using a simplified event-frequency and loss model; calibrate distributions with organization data before production use.",
    }

@app.get("/")
def root():
    return {"project": "CyberSpendAI", "status": "online", "version": APP_VERSION, "docs": "/docs", "health": "/health", "api": "/api/v1"}

@app.get("/health")
def health():
    return {"status": "healthy", "service": "cyberspendai-api", "version": APP_VERSION, "timestamp": datetime.now(timezone.utc).isoformat()}

@app.get("/api/v1")
def api_index():
    return {"endpoints": ["POST /api/v1/risk/analyze", "POST /api/v1/risk/what-if", "POST /api/v1/optimizer/run", "POST /api/v1/data/ingest", "GET /api/v1/metrics/summary"]}

@app.post("/api/v1/risk/analyze")
def analyze_risk(payload: RiskAnalyzeRequest):
    results = [calculate_asset(asset) for asset in payload.assets]
    baseline = sum(x["annualized_loss_exposure_inr"] for x in results)
    residual = sum(x["residual_annual_loss_inr"] for x in results)
    return {
        "status": "success",
        "framework": "FAIR-inspired quantitative loss analysis",
        "currency": INR,
        "portfolio": {
            "asset_count": len(results),
            "baseline_annual_loss_inr": round(baseline, 2),
            "residual_annual_loss_inr": round(residual, 2),
            "estimated_annual_loss_reduction_inr": round(baseline - residual, 2),
            "weighted_average_risk_score": round(sum(x["risk_score"] for x in results) / len(results), 2),
        },
        "assets": results,
        "monte_carlo": simulate_portfolio(payload.assets, payload.simulations, payload.seed, payload.confidence_level),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "disclaimer": "Prototype decision support; not a certified FAIR assessment or actuarial forecast.",
    }

@app.post("/api/v1/risk/what-if")
def what_if(payload: WhatIfRequest):
    before = calculate_asset(payload.asset)
    changed = payload.asset.model_copy(deep=True)
    changed.control_effectiveness = min(1.0, changed.control_effectiveness + payload.control_effectiveness_delta)
    changed.annual_threat_event_frequency *= payload.threat_frequency_multiplier
    changed.primary_loss_inr *= payload.loss_magnitude_multiplier
    changed.secondary_loss_inr *= payload.loss_magnitude_multiplier
    after = calculate_asset(changed)
    delta = before["residual_annual_loss_inr"] - after["residual_annual_loss_inr"]
    return {"status": "success", "before": before, "after": after, "annual_loss_reduction_inr": round(delta, 2), "risk_reduction_percent": round((delta / before["residual_annual_loss_inr"] * 100) if before["residual_annual_loss_inr"] else 0, 2), "scenario": payload.model_dump(exclude={"asset"})}

@app.post("/api/v1/optimizer/run")
def optimize(payload: OptimizerRequest):
    # Greedy marginal loss reduction per rupee. Transparent heuristic, not a global optimum guarantee.
    remaining = payload.budget_inr
    current_loss = payload.baseline_annual_loss_inr
    selected = []
    candidates = [c.model_dump() for c in payload.controls]
    while True:
        feasible = [c for c in candidates if c["cost_inr"] <= remaining]
        if not feasible: break
        best = max(feasible, key=lambda c: (c["risk_reduction"] * current_loss / c["cost_inr"]))
        reduction = current_loss * best["risk_reduction"]
        selected.append({**best, "estimated_annual_loss_reduction_inr": round(reduction, 2), "estimated_roi_percent": round((reduction / best["cost_inr"]) * 100, 2)})
        remaining -= best["cost_inr"]
        current_loss -= reduction
        candidates.remove(best)
    spend = payload.budget_inr - remaining
    reduction_total = payload.baseline_annual_loss_inr - current_loss
    return {"status": "success", "method": "greedy marginal loss reduction per rupee", "budget_inr": payload.budget_inr, "recommended_controls": selected, "total_spend_inr": round(spend, 2), "remaining_budget_inr": round(remaining, 2), "baseline_annual_loss_inr": round(payload.baseline_annual_loss_inr, 2), "projected_residual_annual_loss_inr": round(current_loss, 2), "estimated_annual_loss_reduction_inr": round(reduction_total, 2), "estimated_rosi_percent": round((reduction_total - spend) / spend * 100, 2) if spend else 0, "note": "Control effects are applied sequentially as proportional reductions; real-world control overlap and dependencies are not modeled."}

@app.post("/api/v1/data/ingest")
def ingest(payload: IngestRequest):
    # Validates/normalizes a lightweight ingestion envelope; does not persist data.
    return {"status": "accepted", "source": payload.source, "received_records": len(payload.records), "preview": payload.records[:3], "persisted": False, "message": "Records validated for prototype ingestion. Configure a database and source-specific parsers for durable ingestion."}

@app.get("/api/v1/metrics/summary")
def metrics_summary():
    return {"status": "ok", "supported_sources": ["manual", "siem", "edr", "iam", "cspm", "vulnerability_scanner", "asset_inventory", "threat_intel"], "risk_model": "FAIR-inspired expected loss + simplified Monte Carlo VaR", "optimization": "Greedy ROI heuristic", "persistence": "Not configured", "auth": "Not configured; do not expose sensitive production data without authentication"}

# Backwards-compatible aliases for the earlier simple backend.
@app.post("/risk/analyze")
def legacy_analyze(payload: RiskAnalyzeRequest):
    return analyze_risk(payload)

@app.post("/optimizer/run")
def legacy_optimize(payload: OptimizerRequest):
    return optimize(payload)
