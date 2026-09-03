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
        summary = "AI summary"
        attack_scenario = "AI attack scenario"
        technical_explanation = "AI technical explanation"
        remediation_explanation = "AI remediation"
        analyst_notes = "AI notes"
        prompt_version = "v1"
        finding_hash = "test-hash"

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

def test_cli_multi_finding_report(monkeypatch, capsys):
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
            "findings.json",
            "--ai-provider",
            "mock",
            "--report",
        ],
    )

    cli.main()

    output = capsys.readouterr().out

    assert "# Security Findings Report" in output
    assert "**Total Findings:** 5" in output

    assert output.count("# Security Findings Report") == 1
    assert "# Security Finding Report" not in output

    assert "SQL Injection" in output
    assert "Broken Access Control" in output
    assert "Security Misconfiguration" in output
    assert "Cryptographic Failure" in output
    assert "Authentication Failure" in output

def test_cli_multi_finding_report_orders_by_priority_score(
    monkeypatch,
    capsys,
):
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
            "findings.json",
            "--ai-provider",
            "mock",
            "--report",
        ],
    )

    cli.main()

    output = capsys.readouterr().out

    # Higher-priority findings must appear before lower-priority findings.
    assert output.index("SQL Injection") < output.index(
        "Cryptographic Failure"
    )
    assert output.index("Cryptographic Failure") < output.index(
        "Security Misconfiguration"
    )

    # SQL Injection has the highest P1 score.
    assert output.index("SQL Injection") < output.index(
        "Broken Access Control"
    )
    assert output.index("SQL Injection") < output.index(
        "Authentication Failure"
    )

    # P2 must appear after every P1 finding.
    assert output.index("Security Misconfiguration") > output.index(
        "Authentication Failure"
    )

def test_cli_parses_burp_file(tmp_path, monkeypatch, capsys):
    burp_data = {
        "request": """POST /login HTTP/2
Host: example.com
Content-Type: application/x-www-form-urlencoded
User-Agent: TestBrowser
Cookie: session=secret-session

csrf=test-csrf&username=test&password=test
""",
        "response": """HTTP/2 200 OK
Content-Type: text/html; charset=utf-8

Invalid username or password.
""",
    }

    burp_file = tmp_path / "burp_exchange.json"
    burp_file.write_text(json.dumps(burp_data))

    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "--burp-file",
            str(burp_file),
        ],
    )

    cli.main()

    output = capsys.readouterr().out

    assert "Burp Observation" in output
    assert "POST /login" in output
    assert "Host:      example.com" in output
    assert "Status:    200" in output
    assert "username=test" in output
    assert "password=test" not in output
    assert "secret-session" not in output


def test_cli_burp_json_output(tmp_path, monkeypatch, capsys):
    burp_data = {
        "request": """POST /login HTTP/2
Host: example.com
Content-Type: application/x-www-form-urlencoded

username=test&password=test
""",
        "response": """HTTP/2 200 OK
Content-Type: text/html; charset=utf-8

Invalid username or password.
""",
    }

    burp_file = tmp_path / "burp_exchange.json"
    burp_file.write_text(json.dumps(burp_data))

    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "--burp-file",
            str(burp_file),
            "--json",
        ],
    )

    cli.main()

    output = capsys.readouterr().out
    result = json.loads(output)

    assert result["method"] == "POST"
    assert result["host"] == "example.com"
    assert result["path"] == "/login"
    assert result["response_status"] == 200
    assert result["parameters"]["username"] == "test"
    assert result["parameters"]["password"] == "test"


def test_cli_burp_file_rejects_invalid_exchange(
    tmp_path,
    monkeypatch,
):
    burp_data = {
        "request": "not a valid HTTP request",
        "response": "HTTP/2 200 OK\n\nOK",
    }

    burp_file = tmp_path / "burp_exchange.json"
    burp_file.write_text(json.dumps(burp_data))

    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "--burp-file",
            str(burp_file),
        ],
    )

    try:
        cli.main()
    except ValueError as exc:
        assert "request" in str(exc).lower()
    else:
        raise AssertionError("Expected ValueError")

def test_cli_burp_output_redacts_sensitive_parameters(
    tmp_path,
    monkeypatch,
    capsys,
):
    burp_data = {
        "request": """POST /login HTTP/2
Host: example.com
Content-Type: application/x-www-form-urlencoded

csrf=test-csrf&username=test&password=super-secret
""",
        "response": """HTTP/2 200 OK
Content-Type: text/html; charset=utf-8

Invalid username or password.
""",
    }

    burp_file = tmp_path / "burp.json"
    burp_file.write_text(json.dumps(burp_data))

    monkeypatch.setattr(
        "sys.argv",
        [
            "cli",
            "--burp-file",
            str(burp_file),
        ],
    )

    cli.main()

    output = capsys.readouterr().out

    assert "username=test" in output
    assert "password=[REDACTED]" in output
    assert "csrf=[REDACTED]" in output
    assert "super-secret" not in output
    assert "test-csrf" not in output
