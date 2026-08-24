import argparse
import json

from app.models.finding import Finding
from app.services.triage import triage_finding

def display_finding(finding):
    print("\nAI Security Findings Triage")
    print("─" * 40)
    print(f"Finding:     {finding.title}")
    print(f"Source:      {finding.source}")
    print(f"Severity:    {finding.severity.value} ({finding.severity_score})")
    print(f"Priority:    {finding.priority.value} ({finding.priority_score})")
    print(f"Confidence:  {finding.confidence.value} ({finding.confidence_score})")
    print(f"OWASP:       {finding.owasp_category or 'Not classified'}")

    if finding.url:
        print(f"Endpoint:    {finding.url}")

    if finding.parameter:
        print(f"Parameter:   {finding.parameter}")

    print(f"\nReason:      {finding.priority_reason}")
    print(f"Impact:      {finding.impact_summary or 'Not available'}")

    if finding.recommendation:
        print(f"Fix:         {finding.recommendation}")

    print()

def main():
    parser = argparse.ArgumentParser(
        description="AI Security Findings Triage CLI"
    )

    parser.add_argument(
    "--file",
    required=True,
    help="Path to the finding JSON file",
    )

    args = parser.parse_args()

    with open(args.file, "r") as file:
         data = json.load(file)

    finding = Finding(**data)

    triaged_finding = triage_finding(finding)

    display_finding(triaged_finding)



if __name__ == "__main__":
    main()