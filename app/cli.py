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

def display_summary(findings):
    print()
    print("AI Security Findings Triage")
    print("─" * 40)
    print()
    print(f"{len(findings)} findings analyzed")
    print()

    severity_counts = {}
    priority_counts = {}
    confidence_counts = {}
    owasp_counts = {}

    for finding in findings:
        severity = finding.severity.value
        priority = finding.priority.value
        confidence = finding.confidence.value
        owasp = finding.owasp_category

        severity_counts[severity] = severity_counts.get(severity, 0) + 1
        priority_counts[priority] = priority_counts.get(priority, 0) + 1
        confidence_counts[confidence] = confidence_counts.get(confidence, 0) + 1

        if owasp:
            owasp_counts[owasp] = owasp_counts.get(owasp, 0) + 1

    print("Severity:")
    for name, count in severity_counts.items():
        print(f"  {name}: {count}")

    print()
    print("Priority:")
    for name, count in priority_counts.items():
        print(f"  {name}: {count}")

    print()
    print("Confidence:")
    for name, count in confidence_counts.items():
        print(f"  {name}: {count}")

    print()
    print("OWASP:")
    for name, count in owasp_counts.items():
        print(f"  {name}: {count}")

    print()
    print("─" * 40)

def main():
    parser = argparse.ArgumentParser(
        description="AI Security Findings Triage CLI"
    )

    parser.add_argument(
      "--file",
      required=True,
      help="Path to the finding JSON file",
    )
    parser.add_argument(
      "--json",
      action="store_true",
      help="Output triage results as JSON",
    )

    args = parser.parse_args()

    with open(args.file, "r") as file:
         data = json.load(file)

    if isinstance(data, list):
        findings = [Finding(**item) for item in data]

        for finding in findings:
            triage_finding(finding)
        if args.json:
          print(json.dumps(
              [finding.model_dump(mode="json") for finding in findings],
              indent=2,
          ))
          return

        display_summary(findings)
        priority_order = {
            "P1": 1,
            "P2": 2,
            "P3": 3,
            "P4": 4,
        }


        findings.sort(key=lambda finding: finding.priority.value)

        for finding in findings:
            display_finding(finding)

    else:
        finding = Finding(**data)
        result = triage_finding(finding)
        display_finding(result)




if __name__ == "__main__":
    main()