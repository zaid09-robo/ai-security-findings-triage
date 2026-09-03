from fastapi import FastAPI, HTTPException

from app.models.finding import Finding
from app.services.burp import parse_burp_exchange
from app.services.ai_analysis import analyze_finding
from app.services.ai_provider import get_ai_client
from app.services.report import generate_report
from app.services.triage import triage_finding

app = FastAPI(
    title="AI Security Findings Triage",
    description="Security finding triage and prioritization platform",
    version="0.1.0",
)

findings_store = {}
ai_client = get_ai_client()


@app.get("/")
def root():
    return {
        "message": "AI Security Findings Triage API",
        "status": "running",
    }


@app.post("/burp/parse")
def parse_burp(request_data: dict):
    request = request_data.get("request")
    response = request_data.get("response")

    if not isinstance(request, str) or not isinstance(response, str):
        raise HTTPException(
            status_code=422,
            detail="Both 'request' and 'response' must be strings",
        )

    try:
        observation = parse_burp_exchange(
            raw_request=request,
            raw_response=response,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=400,
            detail=str(exc),
        ) from exc

    return observation


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

@app.get("/findings/{finding_id}/report")
def get_finding_report(finding_id: str):
    if finding_id not in findings_store:
        raise HTTPException(
            status_code=404,
            detail=f"Finding with id '{finding_id}' not found",
        )

    finding = findings_store[finding_id]

    triaged_finding = triage_finding(finding)

    analysis = analyze_finding(
        finding=triaged_finding,
        client=ai_client,
    )

    report = generate_report(
        finding=triaged_finding,
        analysis=analysis,
    )

    return report

@app.get("/findings/{finding_id}")
def get_finding(finding_id: str):
    if finding_id not in findings_store:
        raise HTTPException(
            status_code=404,
            detail=f"Finding with id '{finding_id}' not found",
        )

    return findings_store[finding_id]