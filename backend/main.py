from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests
from ai_service.decision_engine import assess_all
from pentest_engine.ranking_engine import rank_assessments
from pentest_engine.decision_loop import decide_next_action
from pentest_engine.cve_lookup import enrich_with_cves
from fastapi.responses import HTMLResponse
from backend.report_generator import generate_html_report
from fastapi.middleware.cors import CORSMiddleware
from backend.orchestrator import run_full_pipeline


from backend.database import (
    init_db, create_scan_session, update_session_status,
    save_findings, save_execution,
    get_session_findings, get_session_executions, get_all_sessions
)


app = FastAPI(title="Pentivo API")

app = FastAPI(title="Pentivo API")

init_db()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from backend.config import KALI_AGENT_URL, backend_timeout_for

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
            timeout=backend_timeout_for(request.host_range)        )
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
            timeout=backend_timeout_for(request.host_range)        
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
            timeout=backend_timeout_for(request.host_range)     
               )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.ConnectionError:
        raise HTTPException(status_code=503, detail="Cannot reach Kali agent. Is it running?")
    except requests.exceptions.Timeout:
        raise HTTPException(status_code=504, detail="Result analysis timed out.")
    except requests.exceptions.HTTPError as e:
        raise HTTPException(status_code=502, detail=f"Kali agent returned an error: {e}")


class NextActionRequest(BaseModel):
    analysis_result: dict
    ranked_list: list
    current_index: int


@app.post("/next_action")
def next_action(request: NextActionRequest):
    try:
        return decide_next_action(
            request.analysis_result,
            request.ranked_list,
            request.current_index,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decision loop error: {e}")


@app.get("/sessions")
def list_sessions():
    return {"sessions": get_all_sessions()}


@app.get("/sessions/{session_id}/findings")
def session_findings(session_id: int):
    return {"findings": get_session_findings(session_id)}


@app.get("/sessions/{session_id}/executions")
def session_executions(session_id: int):
    return {"executions": get_session_executions(session_id)}


@app.get("/sessions/{session_id}/report", response_class=HTMLResponse)
def session_report(session_id: int):
    return generate_html_report(session_id)


class FullRunRequest(BaseModel):
    target_range: str


@app.post("/full_run")
def full_run(request: FullRunRequest):
    return run_full_pipeline(request.target_range, ai_decide_url=None)