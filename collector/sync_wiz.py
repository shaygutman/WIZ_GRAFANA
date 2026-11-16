import logging
import os
import time
from typing import Any

import psycopg
import requests
from psycopg.types.json import Jsonb


LOG = logging.getLogger("wiz_sync")
ISSUES_QUERY = """
query IssuesPage($first: Int!, $after: String) {
  issuesV2(first: $first, after: $after) {
    nodes {
      id
      severity
      status
      type
      createdAt
      resolvedAt
      description
      entitySnapshot {
        id
        name
        type
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""
UPSERT_ISSUE = """
INSERT INTO wiz_issues (
    id, severity, status, issue_type, created_at, resolved_at,
    description, entity_id, entity_name, entity_type, raw, synced_at
) VALUES (
    %(id)s, %(severity)s, %(status)s, %(issue_type)s,
    %(created_at)s, %(resolved_at)s, %(description)s,
    %(entity_id)s, %(entity_name)s, %(entity_type)s, %(raw)s, NOW()
)
ON CONFLICT (id) DO UPDATE SET
    severity = EXCLUDED.severity,
    status = EXCLUDED.status,
    issue_type = EXCLUDED.issue_type,
    created_at = EXCLUDED.created_at,
    resolved_at = EXCLUDED.resolved_at,
    description = EXCLUDED.description,
    entity_id = EXCLUDED.entity_id,
    entity_name = EXCLUDED.entity_name,
    entity_type = EXCLUDED.entity_type,
    raw = EXCLUDED.raw,
    synced_at = NOW()
"""


def required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ValueError(f"Required environment variable {name} is not set")
    return value


def positive_int(name: str, default: int) -> int:
    value = int(os.environ.get(name, str(default)))
    if value <= 0:
        raise ValueError(f"{name} must be greater than zero")
    return value


def get_access_token(session: requests.Session) -> str:
    response = session.post(
        required_env("WIZ_AUTH_URL"),
        data={
            "grant_type": "client_credentials",
            "client_id": required_env("WIZ_CLIENT_ID"),
            "client_secret": required_env("WIZ_CLIENT_SECRET"),
            "audience": os.environ.get("WIZ_AUDIENCE", "wiz-api"),
        },
        timeout=30,
    )
    response.raise_for_status()
    token = response.json().get("access_token")
    if not token:
        raise RuntimeError("Wiz authentication response did not contain access_token")
    return token


def fetch_page(
    session: requests.Session, token: str, page_size: int, cursor: str | None
) -> dict[str, Any]:
    response = session.post(
        required_env("WIZ_API_URL"),
        headers={"Authorization": f"Bearer {token}"},
        json={
            "query": ISSUES_QUERY,
            "variables": {"first": page_size, "after": cursor},
        },
        timeout=60,
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("errors"):
        raise RuntimeError(f"Wiz GraphQL request failed: {payload['errors']}")
    try:
        return payload["data"]["issuesV2"]
    except (KeyError, TypeError) as exc:
        raise RuntimeError("Wiz GraphQL response did not include data.issuesV2") from exc


def normalize_issue(issue: dict[str, Any]) -> dict[str, Any]:
    entity = issue.get("entitySnapshot") or {}
    issue_id = issue.get("id")
    if not issue_id:
        raise RuntimeError("Wiz returned an issue without an id")
    return {
        "id": issue_id,
        "severity": issue.get("severity"),
        "status": issue.get("status"),
        "issue_type": issue.get("type"),
        "created_at": issue.get("createdAt"),
        "resolved_at": issue.get("resolvedAt"),
        "description": issue.get("description"),
        "entity_id": entity.get("id"),
        "entity_name": entity.get("name"),
        "entity_type": entity.get("type"),
        "raw": Jsonb(issue),
    }


def sync_once() -> int:
    page_size = positive_int("WIZ_PAGE_SIZE", 100)
    with requests.Session() as session:
        token = get_access_token(session)
        cursor = None
        seen_cursors: set[str] = set()
        total = 0

        with psycopg.connect(
            host=required_env("DB_HOST"),
            port=positive_int("DB_PORT", 5432),
            dbname=required_env("DB_NAME"),
            user=required_env("DB_USER"),
            password=required_env("DB_PASSWORD"),
            connect_timeout=10,
        ) as connection:
            while True:
                page = fetch_page(session, token, page_size, cursor)
                issues = page.get("nodes")
                page_info = page.get("pageInfo")
                if not isinstance(issues, list) or not isinstance(page_info, dict):
                    raise RuntimeError("Wiz GraphQL response has an invalid issuesV2 page")

                rows = [normalize_issue(issue) for issue in issues]
                with connection.cursor() as cursor_db:
                    cursor_db.executemany(UPSERT_ISSUE, rows)
                total += len(rows)

                if not page_info.get("hasNextPage"):
                    break
                next_cursor = page_info.get("endCursor")
                if not next_cursor or next_cursor in seen_cursors:
                    raise RuntimeError("Wiz pagination returned a missing or repeated cursor")
                seen_cursors.add(next_cursor)
                cursor = next_cursor

    return total


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    interval = positive_int("SYNC_INTERVAL_SECONDS", 900)
    while True:
        try:
            count = sync_once()
            LOG.info("Wiz sync completed; processed %d issues", count)
        except (requests.RequestException, psycopg.Error, RuntimeError) as exc:
            LOG.exception("Wiz sync failed: %s", exc)
        time.sleep(interval)


if __name__ == "__main__":
    main()
