from app.services.burp import parse_burp_exchange


BURP_REQUEST = """POST /login HTTP/2
Host: example.com
Content-Type: application/x-www-form-urlencoded
User-Agent: TestBrowser
Cookie: session=secret-session

csrf=test-csrf&username=test&password=test
"""

BURP_RESPONSE = """HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 42

Invalid username or password.
"""


def test_parse_burp_exchange_extracts_request_details():
    observation = parse_burp_exchange(BURP_REQUEST, BURP_RESPONSE)

    assert observation.method == "POST"
    assert observation.host == "example.com"
    assert observation.path == "/login"
    assert observation.content_type == "application/x-www-form-urlencoded"

    assert observation.parameters == {
        "csrf": "test-csrf",
        "username": "test",
        "password": "test",
    }


def test_parse_burp_exchange_extracts_response_details():
    observation = parse_burp_exchange(BURP_REQUEST, BURP_RESPONSE)

    assert observation.response_status == 200
    assert observation.response_content_type == "text/html; charset=utf-8"
    assert "Invalid username or password." in observation.response_body


def test_parse_burp_exchange_redacts_sensitive_headers():
    observation = parse_burp_exchange(BURP_REQUEST, BURP_RESPONSE)

    assert "Cookie" not in observation.headers
    assert "session=secret-session" not in observation.raw_request


def test_parse_burp_exchange_preserves_useful_request_headers():
    observation = parse_burp_exchange(BURP_REQUEST, BURP_RESPONSE)

    assert observation.headers["Content-Type"] == (
        "application/x-www-form-urlencoded"
    )
    assert observation.headers["User-Agent"] == "TestBrowser"


def test_parse_burp_exchange_rejects_invalid_request():
    invalid_request = """this is not a valid HTTP request"""

    try:
        parse_burp_exchange(invalid_request, BURP_RESPONSE)
    except ValueError as exc:
        assert "request" in str(exc).lower()
    else:
        raise AssertionError("Expected ValueError")


def test_parse_burp_exchange_rejects_invalid_response():
    invalid_response = """not an HTTP response"""

    try:
        parse_burp_exchange(BURP_REQUEST, invalid_response)
    except ValueError as exc:
        assert "response" in str(exc).lower()
    else:
        raise AssertionError("Expected ValueError")