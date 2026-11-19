import json
import logging
import os
import secrets
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal

import psycopg2
import requests
from fastapi import Depends, FastAPI, Header, HTTPException, Query, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import AwareDatetime, BaseModel, ConfigDict, StringConstraints, field_validator

from wiz_scans import ScanTarget, WizClient


LOG = logging.getLogger("annotation_webhook")


def required_env(name: str) -> str:
    value = os.environ.get(name)
    if not value or not value.strip():
        raise RuntimeError(f"Required environment variable {name} is missing or empty")
    return value


WEBHOOK_TOKEN = required_env("ANNOTATION_WEBHOOK_TOKEN")
DATABASE = {
    "host": required_env("POSTGRES_HOST"),
    "port": os.environ.get("POSTGRES_PORT", "5432"),
    "dbname": required_env("POSTGRES_DB"),
    "user": required_env("POSTGRES_USER"),
    "password": required_env("POSTGRES_PASSWORD"),
    "connect_timeout": 5,
    "options": "-c statement_timeout=10000",
}

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
STATIC = Path(__file__).with_name("static")
app.mount("/scan-assets", StaticFiles(directory=STATIC), name="scan-assets")


def reject_null_characters(value: str | None) -> str | None:
    if value is not None and "\x00" in value:
        raise ValueError("Text fields must not contain null characters")
    return value


class AnnotationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)]
    description: str | None = None
    environment: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=150)
    ]
    tags: Annotated[str, StringConstraints(max_length=100)] = "deploy,cicd"
    event_time: AwareDatetime | None = None

    _validate_text = field_validator("title", "description", "environment", "tags")(
        reject_null_characters
    )

    @field_validator("event_time", mode="before")
    @classmethod
    def parse_event_time(cls, value: object) -> object:
        if value is None or isinstance(value, datetime):
            return value
        if not isinstance(value, str):
            raise ValueError("event_time must be an ISO8601 timestamp with a timezone")
        return datetime.fromisoformat(value)


class AnnotationCreated(BaseModel):
    id: int


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    environment: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=150)
    ] | None = None
    resource_id: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1)
    ] | None = None
    scan_type: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)] = "full"

    _validate_text = field_validator("environment", "resource_id", "scan_type")(
        reject_null_characters
    )


class ScanRecorded(BaseModel):
    annotation_id: int
    status: Literal["recorded"] = "recorded"
    execution_mode: Literal["audit_only"] = "audit_only"
    message: str = (
        "Scan request recorded for manual review. "
        "No Wiz scan or collector synchronization has been queued."
    )


class ScanEnvironment(BaseModel):
    id: str
    name: str


class ScanOutcome(BaseModel):
    target: ScanTarget
    status: Literal["submitted", "failed", "unconfirmed", "not_attempted"]
    message: str


class ScanRunResult(BaseModel):
    annotation_id: int
    status: Literal["submitted", "failed", "partial_failure", "unconfirmed"]
    message: str
    results: list[ScanOutcome]


def require_api_key(
    api_key: Annotated[str | None, Header(alias="X-API-Key")] = None,
) -> None:
    if api_key is None or not secrets.compare_digest(
        api_key.encode("utf-8"), WEBHOOK_TOKEN.encode("utf-8")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
        )


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


def insert_annotation(
    *,
    title: str,
    description: str | None,
    environment: str | None,
    tags: str,
    event_time: datetime | None = None,
) -> int:
    try:
        with closing(psycopg2.connect(**DATABASE)) as connection:
            with connection:
                with connection.cursor() as cursor:
                    cursor.execute(
                        """
                        INSERT INTO wiz_annotations
                            (event_time, title, description, tags, environment)
                        VALUES (COALESCE(%s, NOW()), %s, %s, %s, %s)
                        RETURNING id
                        """,
                        (
                            event_time,
                            title,
                            description,
                            tags,
                            environment,
                        ),
                    )
                    row = cursor.fetchone()
                    if row is None:
                        raise psycopg2.DatabaseError("Annotation insert returned no ID")
        return row[0]
    except psycopg2.Error as exc:
        LOG.error("Annotation insert failed (%s)", type(exc).__name__)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to save annotation",
        ) from exc


@app.post(
    "/api/v1/annotations",
    status_code=status.HTTP_201_CREATED,
    response_model=AnnotationCreated,
    dependencies=[Depends(require_api_key)],
)
def create_annotation(annotation: AnnotationRequest) -> AnnotationCreated:
    return AnnotationCreated(
        id=insert_annotation(
            title=annotation.title,
            description=annotation.description,
            environment=annotation.environment,
            tags=annotation.tags,
            event_time=annotation.event_time,
        )
    )


@app.post(
    "/api/v1/scan",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanRecorded,
    dependencies=[Depends(require_api_key)],
)
def request_scan(scan: ScanRequest) -> ScanRecorded:
    audit = {
        "event": "wiz.scan.requested",
        "execution_mode": "audit_only",
        "scan_started": False,
        **scan.model_dump(),
    }
    annotation_id = insert_annotation(
        title="On-demand Wiz scan requested (audit only)",
        description=json.dumps(audit),
        environment=scan.environment,
        tags="scan,requested,audit-only,wiz",
    )
    return ScanRecorded(annotation_id=annotation_id)


@app.get("/scan", include_in_schema=False)
def scan_form() -> FileResponse:
    return FileResponse(
        STATIC / "scan.html",
        headers={
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": (
                "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
                "base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
            ),
        },
    )


def load_scan_environments() -> list[ScanEnvironment]:
    try:
        with closing(psycopg2.connect(**DATABASE)) as connection:
            with connection, connection.cursor() as cursor:
                cursor.execute("""
                    SELECT subscription_external_id, MAX(subscription_name)
                    FROM wiz_active_issues
                    WHERE cloud_platform = 'AWS' AND subscription_external_id IS NOT NULL
                    GROUP BY subscription_external_id ORDER BY 2, 1
                """)
                return [ScanEnvironment(id=row[0], name=row[1]) for row in cursor.fetchall()]
    except psycopg2.Error as exc:
        LOG.error("Scan environment lookup failed (%s)", type(exc).__name__)
        raise HTTPException(503, "Unable to load scan environments.") from exc


def resolve_scan_environment(value: str) -> ScanEnvironment:
    matches = [
        environment for environment in load_scan_environments()
        if value in (environment.id, environment.name)
    ]
    if not matches:
        raise HTTPException(404, "Environment not found in collected AWS accounts.")
    if len(matches) != 1:
        raise HTTPException(409, "Environment name is ambiguous; use its AWS account ID.")
    return matches[0]


@app.get("/api/v1/scan/environments", dependencies=[Depends(require_api_key)])
def scan_environments() -> list[ScanEnvironment]:
    return load_scan_environments()


@app.get("/api/v1/scan/resources", dependencies=[Depends(require_api_key)])
def scan_resources(
    environment: Annotated[str, Query(min_length=1, max_length=150)],
) -> list[ScanTarget]:
    selected = resolve_scan_environment(environment)
    with requests.Session() as session:
        return WizClient(session).resources(selected.id)


def update_scan_audit(annotation_id: int, result: ScanRunResult) -> None:
    try:
        with closing(psycopg2.connect(**DATABASE)) as connection:
            with connection, connection.cursor() as cursor:
                cursor.execute(
                    "UPDATE wiz_annotations SET description = %s WHERE id = %s",
                    (result.model_dump_json(), annotation_id),
                )
                if cursor.rowcount != 1:
                    raise psycopg2.DatabaseError("Scan audit record is missing")
    except psycopg2.Error as exc:
        LOG.error("Scan audit update failed (%s), annotation_id=%d", type(exc).__name__, annotation_id)
        raise HTTPException(
            503, "Scan requests may already have been submitted, but the audit update failed. "
            "Check Wiz before retrying.",
        ) from exc


@app.post(
    "/api/v1/scan/run",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ScanRunResult,
    dependencies=[Depends(require_api_key)],
)
def run_scan(scan: ScanRequest) -> ScanRunResult | JSONResponse:
    if not scan.environment:
        raise HTTPException(422, "Choose an environment/account before starting a real scan.")
    if scan.scan_type != "full":
        raise HTTPException(422, "Real VM scans support scan_type 'full' only.")
    environment = resolve_scan_environment(scan.environment)
    with requests.Session() as session:
        client = WizClient(session)
        targets = client.resources(environment.id)
        if scan.resource_id:
            targets = [
                target for target in targets
                if scan.resource_id in (target.id, target.resource_id, target.arn)
            ]
            if len(targets) > 1:
                raise HTTPException(409, "Resource ID is ambiguous; use its full ARN.")
        if not targets:
            raise HTTPException(404, "No matching active EC2 instances found in this environment.")
        annotation_id = insert_annotation(
            title="Manual Wiz scan requested",
            description=json.dumps({
                "event": "wiz.scan.submitting",
                "environment": environment.model_dump(),
                "targets": [target.model_dump() for target in targets],
            }),
            environment=environment.name,
            tags="scan,manual,wiz",
        )
        outcomes: list[ScanOutcome] = []
        error_code = None
        for index, target in enumerate(targets):
            try:
                client.start_scan(target)
            except HTTPException as exc:
                error_code = exc.status_code
                outcomes.append(ScanOutcome(
                    target=target,
                    status="failed" if error_code == 403 else "unconfirmed",
                    message=str(exc.detail),
                ))
                outcomes.extend(
                    ScanOutcome(
                        target=remaining, status="not_attempted",
                        message="Stopped after the preceding error; no request sent.",
                    )
                    for remaining in targets[index + 1:]
                )
                break
            outcomes.append(ScanOutcome(
                target=target, status="submitted",
                message="Accepted by Wiz for processing; completion is not yet confirmed.",
            ))
        submitted = sum(outcome.status == "submitted" for outcome in outcomes)
        result = ScanRunResult(
            annotation_id=annotation_id,
            status=(
                "submitted" if error_code is None else "partial_failure" if submitted
                else "failed" if error_code == 403 else "unconfirmed"
            ),
            message=(
                f"Wiz accepted {submitted} scan request(s). Check Wiz for completion and results."
                if error_code is None
                else f"Wiz accepted {submitted} of {len(targets)} requests. "
                "Review the errors below; check Wiz before retrying."
            ),
            results=outcomes,
        )
        update_scan_audit(annotation_id, result)
        if error_code is not None:
            return JSONResponse(
                status_code=207 if submitted else error_code,
                content=result.model_dump(),
            )
        return result
