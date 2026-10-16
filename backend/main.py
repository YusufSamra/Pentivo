from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests

app = FastAPI(title="Pentivo API")

KALI_AGENT_URL = "http://localhost:8001"


class ScanRequest(BaseModel):
    target_range: str


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


class EnumerateRequest(BaseModel):
    host: str


@app.get("/health")
def health():
    return {"status": "healthy", "agent": "kali"}


@app.post("/discover")
def discover(request: DiscoverRequest):
    try:
        hosts = discover_hosts(request.target_range)
        return {
            "target_range": request.target_range,
            "hosts_found": hosts,
            "count": len(hosts)
        }
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/enumerate")
def enumerate(request: EnumerateRequest):
    try:
        result = enumerate_services(request.host)
        return result
    except RuntimeError as e:
        raise HTTPException(status_code=500, detail=str(e))