from pydantic import BaseModel, Field


class BurpObservation(BaseModel):
    method: str
    host: str
    path: str

    headers: dict[str, str] = Field(default_factory=dict)
    content_type: str | None = None
    parameters: dict[str, str] = Field(default_factory=dict)

    response_status: int
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_content_type: str | None = None
    response_body: str = ""

    raw_request: str