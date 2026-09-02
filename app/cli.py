import argparse
import json

from app.models.finding import Finding
from app.services.ai_analysis import analyze_finding
from app.services.ai_provider import get_ai_client
from app.services.triage import triage_finding
from app.services.report import generate_report


def generate_combined_report(findings_with_analysis):
    """Generate a combined Markdown report for multiple findings."""

    sections = [
        "# Security Findings Report",
        "",
        f"**Total Findings:** {len(findings_with_analysis)}",
        "",
        "---",
        "",
    ]

    for index, (finding, analysis) in enumerate(
        findings_with_analysis,
        start=1,
    ):
        report = generate_report(
            finding=finding,
            analysis=analysis,
        )

        finding_markdown = report.markdown

        if finding_markdown.startswith("# Security Finding Report"):
            finding_markdown = finding_markdown[
                len("# Security Finding Report"):].lstrip()

        finding_markdown = finding_markdown.replace(
            "## Finding\n",
            "### Finding\n",
        )
        finding_markdown = finding_markdown.replace(
            "## Triage Results\n",
            "### Triage Results\n",
        )
        finding_markdown = finding_markdown.replace(
            "### Priority Reason\n",
            "#### Priority Reason\n",
        )
        finding_markdown = finding_markdown.replace(
            "### Impact Summary\n",
            "#### Impact Summary\n",
        )
        finding_markdown = finding_markdown.replace(
            "## Finding Details\n",
            "### Finding Details\n",
        )
        finding_markdown = finding_markdown.replace(
            "### Evidence\n",
            "#### Evidence\n",
        )
        finding_markdown = finding_markdown.replace(
            "### Recommendation\n",
            "#### Recommendation\n",
        )
        finding_markdown = finding_markdown.replace(
            "## AI Analysis\n",
            "### AI Analysis\n",
        )
        finding_markdown = finding_markdown.replace(
            "### Summary\n",
            "#### Summary\n",
        )
        finding_markdown = finding_markdown.replace(
            "### Attack Scenario\n",
            "#### Attack Scenario\n",
        )
        finding_markdown = finding_markdown.replace(
            "### Technical Explanation\n",
            "#### Technical Explanation\n",
        )
        finding_markdown = finding_markdown.replace(
            "### Remediation Explanation\n",
            "#### Remediation Explanation\n",
        )
        finding_markdown = finding_markdown.replace(
            "### Analyst Notes\n",
            "#### Analyst Notes\n",
        )
        finding_markdown = finding_markdown.replace(
            "## AI Analysis Metadata\n",
            "### AI Analysis Metadata\n",
        )

        sections.extend(
            [
                f"## Finding {index} — {finding.title}",
                "",
                finding_markdown,
                "",
                "---",
                "",
            ]
        )

    return "\n".join(sections)


def display_finding(finding, analysis=None):
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

    if analysis is not None:
        print("\nAI Analysis")
        print("─" * 40)
        print(f"Status:      {analysis.status}")
        print(f"\nSummary:     {analysis.summary}")
        print(f"\nAttack:      {analysis.attack_scenario}")
        print(f"\nTechnical:   {analysis.technical_explanation}")
        print(f"\nRemediation: {analysis.remediation_explanation}")
        print(f"\nNotes:       {analysis.analyst_notes}")

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

    parser.add_argument(
        "--report",
        action="store_true",
        help="Output a Markdown security report",
    )

    parser.add_argument(
        "--ai-provider",
        choices=["ollama", "mock"],
        default=None,
        help="AI provider (default: Ollama)",
    )

    args = parser.parse_args()

    with open(args.file, "r") as file:
        data = json.load(file)

    client = get_ai_client(args.ai_provider)

    if isinstance(data, list):
        findings = [Finding(**item) for item in data]

        analyses = []

        for finding in findings:
            triage_finding(finding)

            analysis = analyze_finding(
                finding=finding,
                client=client,
            )

            analyses.append(analysis)

        if args.json:
            output = []

            for finding, analysis in zip(findings, analyses):
                finding_data = finding.model_dump(mode="json")
                finding_data["ai_analysis"] = analysis.model_dump(mode="json")
                output.append(finding_data)

            print(json.dumps(output, indent=2))
            return

        findings_with_analysis = list(zip(findings, analyses))
        priority_order = {
            "P1": 1,
            "P2": 2,
            "P3": 3,
            "P4": 4,
        }

        findings_with_analysis.sort(
            key=lambda item: (
                priority_order[item[0].priority.value],
                -item[0].priority_score,
            )
        )

        if args.report:
            print(generate_combined_report(findings_with_analysis))
            return

        display_summary(findings)

        for finding, analysis in findings_with_analysis:
            display_finding(
                finding,
                analysis,
            )
    else:
        finding = Finding(**data)

        result = triage_finding(finding)

        analysis = analyze_finding(
            finding=result,
            client=client,
        )

        if args.json:
            output = result.model_dump(mode="json")
            output["ai_analysis"] = analysis.model_dump(mode="json")

            print(json.dumps(output, indent=2))
            return

        if args.report:
            report = generate_report(
                finding=result,
                analysis=analysis,
            )

            print(report.markdown)
            return

        display_finding(
            result,
            analysis,
        )

if __name__ == "__main__":
    main()
