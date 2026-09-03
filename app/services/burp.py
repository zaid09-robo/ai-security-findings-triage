from urllib.parse import parse_qsl

from app.models.burp import BurpObservation


SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "proxy-authorization",
    "set-cookie",
}


def _parse_http_message(message: str, message_type: str):
    if "\r\n\r\n" in message:
        header_section, body = message.split("\r\n\r\n", 1)
    elif "\n\n" in message:
        header_section, body = message.split("\n\n", 1)
    else:
        header_section = message
        body = ""

    lines = header_section.splitlines()

    if not lines:
        raise ValueError(f"Invalid HTTP {message_type}: missing start line")

    start_line = lines[0].strip()
    headers = {}

    for line in lines[1:]:
        if not line.strip():
            continue

        if ":" not in line:
            raise ValueError(
                f"Invalid HTTP {message_type}: malformed header"
            )

        name, value = line.split(":", 1)
        name = name.strip()
        value = value.strip()

        if name.lower() in SENSITIVE_HEADERS:
            continue

        headers[name] = value

    return start_line, headers, body.strip()


def _sanitize_raw_request(raw_request: str) -> str:
    lines = raw_request.splitlines()
    sanitized_lines = []

    for line in lines:
        if ":" in line:
            name = line.split(":", 1)[0].strip()

            if name.lower() in SENSITIVE_HEADERS:
                continue

        sanitized_lines.append(line)

    return "\n".join(sanitized_lines)


def parse_burp_exchange(
    raw_request: str,
    raw_response: str,
) -> BurpObservation:
    request_line, headers, request_body = _parse_http_message(
        raw_request,
        "request",
    )

    response_line, response_headers, response_body = _parse_http_message(
        raw_response,
        "response",
    )

    request_parts = request_line.split()

    if len(request_parts) < 3:
        raise ValueError("Invalid HTTP request: malformed request line")

    method = request_parts[0]
    target = request_parts[1]

    if not target.startswith("/"):
        raise ValueError("Invalid HTTP request: invalid request target")

    host = headers.get("Host")

    if not host:
        raise ValueError("Invalid HTTP request: missing Host header")

    if not response_line.startswith("HTTP/"):
        raise ValueError("Invalid HTTP response: malformed status line")

    response_parts = response_line.split()

    if len(response_parts) < 2:
        raise ValueError("Invalid HTTP response: missing status code")

    try:
        response_status = int(response_parts[1])
    except ValueError as exc:
        raise ValueError(
            "Invalid HTTP response: invalid status code"
        ) from exc

    content_type = headers.get("Content-Type")
    response_content_type = response_headers.get("Content-Type")

    parameters = dict(
        parse_qsl(
            request_body,
            keep_blank_values=True,
        )
    )

    return BurpObservation(
        method=method,
        host=host,
        path=target,
        headers=headers,
        content_type=content_type,
        parameters=parameters,
        response_status=response_status,
        response_headers=response_headers,
        response_content_type=response_content_type,
        response_body=response_body,
        raw_request=_sanitize_raw_request(raw_request),
    )
