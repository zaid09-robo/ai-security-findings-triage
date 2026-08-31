import json

from app import cli


def test_cli_runs_ai_analysis(monkeypatch, capsys):
    class FakeAIAnalysis:
        status = "success"
        summary = "AI summary"
        attack_scenario = "AI attack scenario"
        technical_explanation = "AI technical explanation"
        remediation_explanation = "AI remediation"
        analyst_notes = "AI notes"

    def fake_analyze_finding(finding, client):
        assert finding.severity.value == "Critical"
        assert finding.priority.value == "P1"
        assert finding.confidence.value == "High"
        return FakeAIAnalysis()

    monkeypatch.setattr(
        cli,
        "analyze_finding",
        fake_analyze_finding,
    )

    monkeypatch.setattr(
        cli,
        "get_ai_client",
        lambda provider: object(),
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "--file",
            "finding.json",
            "--ai-provider",
            "mock",
        ],
    )

    cli.main()

    output = capsys.readouterr().out

    assert "AI Analysis" in output
    assert "Status:      success" in output
    assert "AI summary" in output
    assert "Severity:    Critical (24)" in output
    assert "Priority:    P1 (17)" in output
    assert "Confidence:  High (22)" in output


def test_cli_json_includes_ai_analysis(monkeypatch, capsys):
    class FakeAIAnalysis:
        def model_dump(self, mode="json"):
            return {
                "summary": "AI summary",
                "attack_scenario": "AI attack scenario",
                "technical_explanation": "AI technical explanation",
                "remediation_explanation": "AI remediation",
                "analyst_notes": "AI notes",
                "prompt_version": "v1",
                "finding_hash": "test-hash",
                "status": "success",
            }

    def fake_analyze_finding(finding, client):
        return FakeAIAnalysis()

    monkeypatch.setattr(
        cli,
        "analyze_finding",
        fake_analyze_finding,
    )

    monkeypatch.setattr(
        cli,
        "get_ai_client",
        lambda provider: object(),
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "--file",
            "finding.json",
            "--ai-provider",
            "mock",
            "--json",
        ],
    )

    cli.main()

    output = capsys.readouterr().out
    result = json.loads(output)

    assert result["severity"] == "Critical"
    assert result["priority"] == "P1"
    assert result["confidence"] == "High"

    assert "ai_analysis" in result
    assert result["ai_analysis"]["status"] == "success"
    assert result["ai_analysis"]["summary"] == "AI summary"


def test_cli_passes_selected_provider(monkeypatch, capsys):
    selected_provider = None

    class FakeAIAnalysis:
        status = "success"
        summary = "summary"
        attack_scenario = "attack"
        technical_explanation = "technical"
        remediation_explanation = "remediation"
        analyst_notes = "notes"

    def fake_get_ai_client(provider):
        nonlocal selected_provider
        selected_provider = provider
        return object()

    monkeypatch.setattr(
        cli,
        "get_ai_client",
        fake_get_ai_client,
    )

    monkeypatch.setattr(
        cli,
        "analyze_finding",
        lambda finding, client: FakeAIAnalysis(),
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "--file",
            "finding.json",
            "--ai-provider",
            "mock",
        ],
    )

    cli.main()

    capsys.readouterr()

    assert selected_provider == "mock"
