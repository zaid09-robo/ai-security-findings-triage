from fastapi import FastAPI, HTTPException

from app.models.finding import Finding

app = FastAPI(
    title="AI Security Findings Triage",
    description="Security finding triage and prioritization platform",
    version="0.1.0",
)

findings_store = {}

@app.get("/")
def root():
    return {
        "message": "AI Security Findings Triage API",
        "status": "running",
    }


@app.post("/findings", status_code=201)
def create_finding(finding: Finding):
    if finding.id in findings_store:
        raise HTTPException(
            status_code=409,
            detail=f"Finding with id '{finding.id}' already exists",
        )

    findings_store[finding.id] = finding

    return finding

@app.get("/findings")
def get_findings():
    return list(findings_store.values())

@app.get("/findings/{finding_id}")
def get_finding(finding_id: str):
    if finding_id not in findings_store:
        raise HTTPException(
            status_code=404,
            detail=f"Finding with id '{finding_id}' not found",
        )

    return findings_store[finding_id]    