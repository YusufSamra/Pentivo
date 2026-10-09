from fastapi import FastAPI

app = FastAPI(title="Pentivo API")


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