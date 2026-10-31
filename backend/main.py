from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
from ai_service.decision_engine import assess_all

from pentest_engine.cve_lookup import enrich_with_cves

app = FastAPI(title="Pentivo API")

KALI_AGENT_URL = "http://localhost:8001"


class ScanRequest(BaseModel):
    target_range: str


class EnumerateRequest(BaseModel):
    host_range: str


class AnalyzeRequest(BaseModel):
    host_range: str


@app.get("/")
def root():
    return {
        "project": "Pentivo",
        "status": "running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy"
    }


@app.post("/scan")
def scan(request: ScanRequest):
    try:
        response = requests.post(
            f"{KALI_AGENT_URL}/discover",
            json={"target_range": request.target_range},
            timeout=130
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        raise HTTPException(
            status_code=503,
            detail="Cannot reach Kali agent. Is it running?"
        )
    except requests.exceptions.Timeout:
        raise HTTPException(
            status_code=504,
            detail="Scan timed out."
        )
    except requests.exceptions.HTTPError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Kali agent returned an error: {e}"
        )


@app.post("/enumerate")
def enumerate(request: EnumerateRequest):
    try:
        response = requests.post(
            f"{KALI_AGENT_URL}/enumerate",
            json={"host_range": request.host_range},
            timeout=400
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        raise HTTPException(
            status_code=503,
            detail="Cannot reach Kali agent. Is it running?"
        )
    except requests.exceptions.Timeout:
        raise HTTPException(
            status_code=504,
            detail="Enumeration timed out."
        )
    except requests.exceptions.HTTPError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Kali agent returned an error: {e}"
        )


@app.post("/analyze")
def analyze(request: AnalyzeRequest):
    try:
        enum_response = requests.post(
            f"{KALI_AGENT_URL}/enumerate",
            json={"host_range": request.host_range},
            timeout=400
        )
        enum_response.raise_for_status()
        enum_data = enum_response.json()

        enriched = enrich_with_cves(enum_data["results"])

        return {"results": enriched}
    except requests.exceptions.ConnectionError:
        raise HTTPException(
            status_code=503,
            detail="Cannot reach Kali agent. Is it running?"
        )
    except requests.exceptions.Timeout:
        raise HTTPException(
            status_code=504,
            detail="Analysis timed out."
        )
    except requests.exceptions.HTTPError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Kali agent returned an error: {e}"
        )


class DecideRequest(BaseModel):
    results: list


@app.post("/decide")
def decide(request: DecideRequest):
    try:
        assessments = assess_all(request.results)
        return {"assessments": assessments}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"AI service error: {e}")