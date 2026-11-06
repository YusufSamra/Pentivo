from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
from ai_service.decision_engine import assess_all
from pentest_engine.ranking_engine import rank_assessments

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


class RankRequest(BaseModel):
    assessments: list


@app.post("/rank")
def rank(request: RankRequest):
    try:
        return rank_assessments(request.assessments)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ranking error: {e}")

class RunRequest(BaseModel):
    ranked: list


@app.post("/run")
def run(request: RunRequest):
    target_item = None
    for item in request.ranked:
        if item.get("ready_to_execute"):
            target_item = item
            break

    if not target_item:
        return {
            "executed": False,
            "message": "No ranked vulnerability is ready to execute (no verified Metasploit module mapped)."
        }

    try:
        response = requests.post(
            f"{KALI_AGENT_URL}/execute",
            json={
                "target": target_item["host"],
                "exploit_info": target_item["exploit_info"]
            },
            timeout=120
        )
        response.raise_for_status()
        return {
            "executed": True,
            "target_item": target_item,
            "result": response.json()
        }
    except requests.exceptions.ConnectionError:
        raise HTTPException(status_code=503, detail="Cannot reach Kali agent. Is it running?")
    except requests.exceptions.Timeout:
        raise HTTPException(status_code=504, detail="Execution timed out.")
    except requests.exceptions.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Kali agent returned an error: {e}")


class AnalyzeResultRequest(BaseModel):
    execution_result: dict


@app.post("/analyze_result")
def analyze_result(request: AnalyzeResultRequest):
    try:
        response = requests.post(
            f"{KALI_AGENT_URL}/analyze_result",
            json={"execution_result": request.execution_result},
            timeout=60
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        raise HTTPException(status_code=503, detail="Cannot reach Kali agent. Is it running?")
    except requests.exceptions.Timeout:
        raise HTTPException(status_code=504, detail="Result analysis timed out.")
    except requests.exceptions.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Kali agent returned an error: {e}")