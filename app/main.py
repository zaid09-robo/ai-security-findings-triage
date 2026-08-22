from fastapi import FastAPI

from app.models.finding import Finding

app = FastAPI(
    title="AI Security Findings Triage",
    description="Security finding triage and prioritization platform",
    version="0.1.0",
)


@app.get("/")
def root():
    return {
        "message": "AI Security Findings Triage API",
        "status": "running",
    }


@app.post("/findings")
def create_finding(finding: Finding):
    return {
        "message": "Finding accepted",
        "finding": finding,
    }
