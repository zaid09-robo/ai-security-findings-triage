from app.models.ai_analysis import AIAnalysis
from app.models.finding import Finding
from app.models.report import SecurityReport


def generate_markdown_report(
    finding: Finding,
    analysis: AIAnalysis,
) -> str:
    """Generate a human-readable Markdown security report."""

    return f"""# Security Finding Report

## Finding

**Title:** {finding.title}

**Source:** {finding.source}

**OWASP Category:** {finding.owasp_category or "Not classified"}

**Endpoint:** {finding.url or "Not provided"}

**Parameter:** {finding.parameter or "Not provided"}

---

## Triage Results

| Metric | Result | Score |
|---|---|---:|
| Severity | {finding.severity.value} | {finding.severity_score} |
| Priority | {finding.priority.value} | {finding.priority_score} |
| Confidence | {finding.confidence.value} | {finding.confidence_score} |

### Priority Reason

{finding.priority_reason}

### Impact Summary

{finding.impact_summary or "Not available"}

---

## Finding Details

{finding.description}

### Evidence

{finding.evidence or "No evidence provided."}

### Recommendation

{finding.recommendation or "No recommendation provided."}

---

## AI Analysis

### Summary

{analysis.summary}

### Attack Scenario

{analysis.attack_scenario}

### Technical Explanation

{analysis.technical_explanation}

### Remediation Explanation

{analysis.remediation_explanation}

### Analyst Notes

{analysis.analyst_notes}

---

## AI Analysis Metadata

**Status:** {analysis.status}

**Prompt Version:** {analysis.prompt_version}

**Finding Hash:** `{analysis.finding_hash}`
"""


def generate_report(
    finding: Finding,
    analysis: AIAnalysis,
) -> SecurityReport:
    """Generate a structured security report."""

    markdown = generate_markdown_report(
        finding=finding,
        analysis=analysis,
    )

    return SecurityReport(
        finding=finding,
        ai_analysis=analysis,
        markdown=markdown,
    )