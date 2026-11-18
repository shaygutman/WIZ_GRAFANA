import logging
import os
import re
import time
from collections import Counter
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any

import psycopg
import requests
from psycopg.types.json import Jsonb
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


LOG = logging.getLogger("wiz_sync")
ISSUES_QUERY = """
query IssuesPage($first: Int!, $after: String, $filterBy: IssueFilters!) {
  issuesV2(first: $first, after: $after, filterBy: $filterBy) {
    nodes {
      id
      severity
      status
      type
      createdAt
      resolvedAt
      description
      sourceRules { name }
      entitySnapshot {
        id
        name
        type
        cloudPlatform
        subscriptionName
        subscriptionExternalId
      }
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
"""
VULNERABILITIES_QUERY = """
query VulnerabilitiesPage($first: Int!, $after: String, $filterBy: VulnerabilityFindingFilters!) {
  vulnerabilityFindings(first: $first, after: $after, filterBy: $filterBy) {
    nodes {
      id name severity status firstDetectedAt resolvedAt
      vulnerabilityExternalId nvdScore CVSSSeverity
      detailedName version fixedVersion locationPath
      hasExploit hasCisaKevExploit
      artifactType { group }
      vulnerableAsset {
        ... on VulnerableAssetBase {
          id name type cloudPlatform subscriptionName subscriptionExternalId
        }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""
POSTURE_QUERY = """
query PosturePage($first: Int!, $after: String, $filterBy: PostureIssueFilters!) {
  postureIssues(first: $first, after: $after, filterBy: $filterBy) {
    nodes {
      id name type status severity createdAt resolvedAt
      policy { name }
      groupEntity {
        ... on PostureIssueGroupGraphEntity {
          entity { id name type properties }
        }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""
CATEGORIES = {
    "issuesV2": "Risk Issues",
    "vulnerabilityFindings": "Vulnerability Management",
    "postureIssues": "Posture Issues",
    "cicdScans": "CI/CD Scans",
}
SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS wiz_annotations (
    id SERIAL PRIMARY KEY,
    event_time TIMESTAMPTZ DEFAULT NOW(),
    title VARCHAR(255),
    description TEXT,
    tags VARCHAR(100),
    environment VARCHAR(150)
);
GRANT SELECT ON wiz_annotations TO grafana_ro;
CREATE TABLE IF NOT EXISTS wiz_active_issues (
    id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    status TEXT NOT NULL,
    severity TEXT NOT NULL,
    created_at TIMESTAMPTZ,
    subscription_name TEXT NOT NULL,
    subscription_id TEXT,
    cloud_platform TEXT NOT NULL,
    rule_name TEXT,
    resource_id TEXT,
    resource_name TEXT,
    resource_type TEXT,
    raw JSONB NOT NULL,
    synced_at TIMESTAMPTZ NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE
);
ALTER TABLE wiz_active_issues ADD COLUMN IF NOT EXISTS category VARCHAR(50);
ALTER TABLE wiz_active_issues ADD COLUMN IF NOT EXISTS subscription_external_id VARCHAR(50);
ALTER TABLE wiz_active_issues ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;
UPDATE wiz_active_issues
SET subscription_external_id = COALESCE(
    subscription_id,
    raw #>> '{entitySnapshot,subscriptionExternalId}',
    raw #>> '{vulnerableAsset,subscriptionExternalId}',
    raw #>> '{groupEntity,entity,properties,subscriptionExternalId}'
)
WHERE subscription_external_id IS NULL;
UPDATE wiz_active_issues SET resolved_at = (raw ->> 'resolvedAt')::TIMESTAMPTZ
WHERE status = 'RESOLVED' AND resolved_at IS NULL AND raw ->> 'resolvedAt' IS NOT NULL;
CREATE INDEX IF NOT EXISTS wiz_active_issues_dashboard_idx
    ON wiz_active_issues (subscription_name, category, severity)
    WHERE is_active AND status = 'OPEN' AND cloud_platform = 'AWS';
CREATE INDEX IF NOT EXISTS wiz_active_issues_account_status_time_idx
    ON wiz_active_issues (subscription_external_id, status, created_at);
CREATE INDEX IF NOT EXISTS wiz_active_issues_resolved_time_idx
    ON wiz_active_issues (resolved_at, subscription_external_id) WHERE status = 'RESOLVED';
CREATE TABLE IF NOT EXISTS wiz_snapshots (
    id BIGSERIAL PRIMARY KEY,
    captured_at TIMESTAMPTZ NOT NULL,
    subscription_name TEXT NOT NULL,
    cloud_platform TEXT NOT NULL,
    severity TEXT NOT NULL,
    issue_count BIGINT NOT NULL CHECK (issue_count >= 0)
);
ALTER TABLE wiz_snapshots ADD COLUMN IF NOT EXISTS category VARCHAR(50);
ALTER TABLE wiz_snapshots ADD COLUMN IF NOT EXISTS metric_type TEXT;
ALTER TABLE wiz_snapshots ADD COLUMN IF NOT EXISTS vuln_type TEXT;
ALTER TABLE wiz_snapshots ADD COLUMN IF NOT EXISTS recorded_at TIMESTAMPTZ
    GENERATED ALWAYS AS (captured_at) STORED;
UPDATE wiz_snapshots SET metric_type = 'VULNERABILITY', vuln_type = 'Unknown'
    WHERE category = 'Vulnerability Management' AND metric_type IS NULL;
CREATE INDEX IF NOT EXISTS wiz_snapshots_time_idx ON wiz_snapshots (captured_at);
CREATE INDEX IF NOT EXISTS wiz_snapshots_metric_time_idx ON wiz_snapshots (metric_type, recorded_at);
CREATE TABLE IF NOT EXISTS wiz_collection_status (
    category VARCHAR(50) PRIMARY KEY,
    available BOOLEAN NOT NULL,
    checked_at TIMESTAMPTZ NOT NULL,
    last_success_at TIMESTAMPTZ,
    detail TEXT NOT NULL
);
GRANT SELECT ON wiz_active_issues, wiz_snapshots, wiz_collection_status TO grafana_ro;
CREATE TABLE IF NOT EXISTS wiz_vulnerabilities (
    finding_id TEXT PRIMARY KEY REFERENCES wiz_active_issues (id),
    vulnerability_id TEXT,
    cve_id TEXT,
    cvss_score DOUBLE PRECISION CHECK (cvss_score BETWEEN 0 AND 10),
    cvss_severity TEXT,
    package_name TEXT,
    installed_version TEXT,
    fixed_version TEXT,
    package_path TEXT,
    exploit_available BOOLEAN,
    known_exploited BOOLEAN
);
CREATE INDEX IF NOT EXISTS wiz_vulnerabilities_cve_idx ON wiz_vulnerabilities (cve_id);
ALTER TABLE wiz_vulnerabilities ADD COLUMN IF NOT EXISTS vuln_type TEXT;
ALTER TABLE wiz_vulnerabilities ADD COLUMN IF NOT EXISTS subscription_external_id VARCHAR(50);
ALTER TABLE wiz_vulnerabilities ADD COLUMN IF NOT EXISTS resolved_at TIMESTAMPTZ;
UPDATE wiz_vulnerabilities v SET
    subscription_external_id = COALESCE(v.subscription_external_id, a.subscription_external_id),
    resolved_at = COALESCE(v.resolved_at, a.resolved_at)
FROM wiz_active_issues a WHERE a.id = v.finding_id AND (
    (v.subscription_external_id IS NULL AND a.subscription_external_id IS NOT NULL)
    OR (v.resolved_at IS NULL AND a.resolved_at IS NOT NULL)
);
GRANT SELECT ON wiz_vulnerabilities TO grafana_ro;
"""
UPSERT_VULNERABILITY = """
INSERT INTO wiz_vulnerabilities (
    finding_id, vulnerability_id, cve_id, cvss_score, cvss_severity,
    package_name, installed_version, fixed_version, package_path,
    exploit_available, known_exploited, vuln_type, subscription_external_id, resolved_at
) VALUES (
    %(finding_id)s, %(vulnerability_id)s, %(cve_id)s, %(cvss_score)s,
    %(cvss_severity)s, %(package_name)s, %(installed_version)s,
    %(fixed_version)s, %(package_path)s, %(exploit_available)s, %(known_exploited)s,
    %(vuln_type)s, %(subscription_external_id)s, %(resolved_at)s
)
ON CONFLICT (finding_id) DO UPDATE SET
    vulnerability_id = EXCLUDED.vulnerability_id,
    cve_id = EXCLUDED.cve_id, cvss_score = EXCLUDED.cvss_score,
    cvss_severity = EXCLUDED.cvss_severity, package_name = EXCLUDED.package_name,
    installed_version = EXCLUDED.installed_version,
    fixed_version = EXCLUDED.fixed_version, package_path = EXCLUDED.package_path,
    exploit_available = EXCLUDED.exploit_available,
    known_exploited = EXCLUDED.known_exploited,
    vuln_type = EXCLUDED.vuln_type,
    subscription_external_id = COALESCE(EXCLUDED.subscription_external_id, wiz_vulnerabilities.subscription_external_id),
    resolved_at = CASE WHEN %(status)s = 'RESOLVED'
        THEN COALESCE(EXCLUDED.resolved_at, wiz_vulnerabilities.resolved_at)
        ELSE EXCLUDED.resolved_at END
"""
UPSERT_ACTIVE = """
INSERT INTO wiz_active_issues (
    id, source, status, severity, created_at, subscription_name, subscription_id,
    cloud_platform, rule_name, resource_id, resource_name, resource_type,
    raw, synced_at, is_active, category, subscription_external_id, resolved_at
) VALUES (
    %(id)s, %(source)s, %(status)s, %(severity)s, %(created_at)s,
    %(subscription_name)s, %(subscription_id)s, %(cloud_platform)s,
    %(rule_name)s, %(resource_id)s, %(resource_name)s, %(resource_type)s,
    %(raw)s, %(synced_at)s, %(is_active)s, %(category)s,
    %(subscription_external_id)s, %(resolved_at)s
)
ON CONFLICT (id) DO UPDATE SET
    status = EXCLUDED.status, severity = EXCLUDED.severity,
    created_at = EXCLUDED.created_at,
    subscription_name = EXCLUDED.subscription_name,
    subscription_id = EXCLUDED.subscription_id,
    subscription_external_id = COALESCE(EXCLUDED.subscription_external_id, wiz_active_issues.subscription_external_id),
    resolved_at = CASE WHEN EXCLUDED.status = 'RESOLVED'
        THEN COALESCE(EXCLUDED.resolved_at, wiz_active_issues.resolved_at)
        ELSE EXCLUDED.resolved_at END,
    cloud_platform = EXCLUDED.cloud_platform, rule_name = EXCLUDED.rule_name,
    resource_id = EXCLUDED.resource_id, resource_name = EXCLUDED.resource_name,
    resource_type = EXCLUDED.resource_type, raw = EXCLUDED.raw,
    synced_at = EXCLUDED.synced_at, is_active = EXCLUDED.is_active,
    category = EXCLUDED.category
"""
INSERT_SNAPSHOTS = """
WITH environments AS (
    SELECT DISTINCT subscription_name FROM wiz_active_issues
    WHERE cloud_platform = 'AWS'
), severities(severity) AS (
    VALUES ('CRITICAL'), ('HIGH'), ('MEDIUM'), ('LOW')
), category_types AS (
    SELECT c.category, t.vuln_type
    FROM wiz_collection_status c
    CROSS JOIN LATERAL (
        SELECT DISTINCT COALESCE(v.vuln_type, 'Unknown') AS vuln_type
        FROM wiz_vulnerabilities v
        WHERE c.category = 'Vulnerability Management'
        UNION
        SELECT 'Unknown' WHERE c.category = 'Vulnerability Management'
        UNION
        SELECT NULL WHERE c.category <> 'Vulnerability Management'
    ) t
    WHERE c.available
), counts AS (
    SELECT a.subscription_name, a.category, a.severity,
        CASE WHEN a.category = 'Vulnerability Management'
            THEN COALESCE(v.vuln_type, 'Unknown') END AS vuln_type,
        COUNT(*) AS issue_count
    FROM wiz_active_issues a
    LEFT JOIN wiz_vulnerabilities v ON v.finding_id = a.id
    WHERE a.is_active AND a.status = 'OPEN' AND a.cloud_platform = 'AWS'
    GROUP BY a.subscription_name, a.category, a.severity, 4
)
INSERT INTO wiz_snapshots (
    captured_at, subscription_name, cloud_platform, category, severity, issue_count,
    metric_type, vuln_type
)
SELECT %s, e.subscription_name, 'AWS', c.category, s.severity,
    COALESCE(n.issue_count, 0),
    CASE WHEN c.category = 'Vulnerability Management' THEN 'VULNERABILITY' END,
    c.vuln_type
FROM environments e
CROSS JOIN category_types c
CROSS JOIN severities s
LEFT JOIN counts n ON n.subscription_name = e.subscription_name
    AND n.category = c.category AND n.severity = s.severity
    AND n.vuln_type IS NOT DISTINCT FROM c.vuln_type
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


def graphql(
    session: requests.Session, token: str, query: str, variables: dict[str, Any]
) -> dict[str, Any]:
    response = session.post(
        required_env("WIZ_API_URL"),
        headers={"Authorization": f"Bearer {token}"},
        json={
            "query": query,
            "variables": variables,
        },
        timeout=60,
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise RuntimeError("Wiz GraphQL response must be an object")
    if payload.get("errors"):
        raise GraphQLError(payload["errors"])
    data = payload.get("data")
    if not isinstance(data, dict):
        raise RuntimeError("Wiz GraphQL response did not include data")
    return data


class GraphQLError(RuntimeError):
    def __init__(self, errors: list[dict[str, Any]]) -> None:
        self.errors = errors
        super().__init__(f"Wiz GraphQL request failed: {errors}")


def pages(
    session: requests.Session, token: str, source: str, query: str, page_size: int,
    filters: dict[str, Any] | None = None,
) -> Iterator[list[dict[str, Any]]]:
    cursor = None
    seen_cursors: set[str] = set()
    while True:
        data = graphql(
            session, token, query,
            {"first": page_size, "after": cursor, "filterBy": filters},
        )
        page = data.get(source)
        if not isinstance(page, dict):
            raise RuntimeError(f"Wiz response did not include {source}")
        nodes, page_info = page.get("nodes"), page.get("pageInfo")
        if (
            not isinstance(nodes, list)
            or not all(isinstance(node, dict) for node in nodes)
            or not isinstance(page_info, dict)
            or not isinstance(page_info.get("hasNextPage"), bool)
        ):
            raise RuntimeError(f"Wiz returned an invalid {source} page")
        yield nodes
        if not page_info["hasNextPage"]:
            break
        next_cursor = page_info.get("endCursor")
        if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen_cursors:
            raise RuntimeError(f"Wiz {source} pagination returned a missing or repeated cursor")
        seen_cursors.add(next_cursor)
        cursor = next_cursor


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


def normalize_finding(
    issue: dict[str, Any], source: str, accounts: dict[str, str], synced_at: datetime
) -> dict[str, Any]:
    if source not in CATEGORIES or not issue.get("id"):
        raise RuntimeError(f"Unknown source or missing finding id: {source}")
    category = CATEGORIES[source]
    if source == "vulnerabilityFindings":
        entity = issue.get("vulnerableAsset") or {}
        rule_name = issue.get("name")
        created_at = issue.get("firstDetectedAt")
    elif source == "postureIssues":
        entity = (issue.get("groupEntity") or {}).get("entity") or {}
        props = entity.get("properties") or {}
        entity = {**entity, **{
            key: props.get(key)
            for key in ("cloudPlatform", "subscriptionName", "subscriptionExternalId")
        }}
        rule_name = (issue.get("policy") or {}).get("name") or issue.get("name")
        created_at = issue.get("createdAt")
    else:
        entity = issue.get("entitySnapshot") or {}
        rules = issue.get("sourceRules") or []
        rule_name = "; ".join(sorted({rule["name"] for rule in rules if rule.get("name")}))
        created_at = issue.get("createdAt")
        if issue.get("type") == "CLOUD_CONFIGURATION":
            category = "Posture Issues"
        elif issue.get("type") not in {
            "TOXIC_COMBINATION", "THREAT_DETECTION", "ATTACK_SURFACE",
            "RISK_TOXIC_COMBINATION", "RISK_AGENT",
        }:
            raise RuntimeError(f"Unmapped Wiz issue type: {issue.get('type')}")
    status, severity = issue.get("status"), issue.get("severity")
    if status not in {"OPEN", "IN_PROGRESS", "RESOLVED", "REJECTED"} or not severity:
        raise RuntimeError(f"Invalid status/severity in {source}")
    account_id = entity.get("subscriptionExternalId")
    account_name = entity.get("subscriptionName")
    if account_id and account_name:
        accounts[account_id] = account_name
    return {
        "id": f"{source}:{issue['id']}",
        "source": source, "category": category, "status": status, "severity": severity,
        "created_at": created_at,
        "subscription_id": account_id,
        "subscription_external_id": account_id,
        "resolved_at": issue.get("resolvedAt") if status == "RESOLVED" else None,
        "subscription_name": account_name or accounts.get(account_id) or account_id or "(unassigned)",
        "cloud_platform": entity.get("cloudPlatform") or "UNKNOWN",
        "rule_name": rule_name, "resource_id": entity.get("id"),
        "resource_name": entity.get("name"), "resource_type": entity.get("type"),
        "raw": Jsonb(issue), "synced_at": synced_at,
        "is_active": status in {"OPEN", "IN_PROGRESS"},
    }


def record_coverage(
    connection: psycopg.Connection, category: str, available: bool, detail: str
) -> None:
    connection.execute(
        """
        INSERT INTO wiz_collection_status (category, available, checked_at, last_success_at, detail)
        VALUES (%s, %s, NOW(), CASE WHEN %s THEN NOW() END, %s)
        ON CONFLICT (category) DO UPDATE SET available = EXCLUDED.available,
            checked_at = EXCLUDED.checked_at, detail = EXCLUDED.detail,
            last_success_at = CASE WHEN EXCLUDED.available THEN EXCLUDED.last_success_at
                ELSE wiz_collection_status.last_success_at END
        """,
        (category, available, available, detail),
    )


def normalize_vulnerability(issue: dict[str, Any]) -> dict[str, Any]:
    if not issue.get("id"):
        raise RuntimeError("Wiz returned a vulnerability finding without an id")
    identifier = issue.get("vulnerabilityExternalId")
    cve_id = None
    if identifier and re.fullmatch(r"CVE-\d{4}-\d{4,}", identifier, flags=re.IGNORECASE):
        cve_id = identifier.upper()
    return {
        "finding_id": f"vulnerabilityFindings:{issue['id']}",
        "status": issue.get("status"),
        "subscription_external_id": (issue.get("vulnerableAsset") or {}).get("subscriptionExternalId"),
        "resolved_at": issue.get("resolvedAt") if issue.get("status") == "RESOLVED" else None,
        "vulnerability_id": identifier,
        "cve_id": cve_id,
        "cvss_score": issue.get("nvdScore"),
        "cvss_severity": issue.get("CVSSSeverity"),
        "package_name": issue.get("detailedName"),
        "installed_version": issue.get("version"),
        "fixed_version": issue.get("fixedVersion"),
        "package_path": issue.get("locationPath"),
        "exploit_available": issue.get("hasExploit"),
        "known_exploited": issue.get("hasCisaKevExploit"),
        "vuln_type": vulnerability_type(issue),
    }


def vulnerability_type(issue: dict[str, Any]) -> str:
    group = (issue.get("artifactType") or {}).get("group")
    return {
        "OS_PACKAGE": "OS Package",
        "CODE_LIBRARY": "Application Library",
        "HOSTED_TECHNOLOGY": "Hosted Technology",
        "PLUGIN": "Plugin",
        "CUSTOM": "Custom",
        "CI_COMPONENT": "CI Component",
        "IDE_EXTENSION": "IDE Extension",
        "UNKNOWN": "Unknown",
    }.get(group, group or "Unknown")


def cicd_unavailable_reason(session: requests.Session, token: str) -> str:
    try:
        graphql(session, token, "{ cicdScans(first: 1) { totalCount } }", {})
    except GraphQLError as exc:
        if not all(
            error.get("extensions", {}).get("code") in {"UNAUTHORIZED", "FORBIDDEN"}
            for error in exc.errors
        ):
            raise
        return "CI/CD unavailable: API client requires read:security_scans."
    return (
        "CI/CD unavailable: scan access granted, but scan-result finding ingestion "
        "must be configured; scan executions are not treated as open findings."
    )


def finding_filters(source: str, resolved_after: datetime | None = None) -> dict[str, Any]:
    statuses = ["RESOLVED"] if resolved_after is not None else ["OPEN", "IN_PROGRESS"]
    filters: dict[str, Any] = {
        "status": {"equals": statuses} if source == "postureIssues" else statuses,
    }
    if source == "vulnerabilityFindings":
        filters.update(cloudPlatforms=["AWS"], severity=["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    if resolved_after is not None:
        filters["resolvedAt"] = {"after": resolved_after.isoformat()}
    return filters


def sync_once() -> Counter[str]:
    page_size = positive_int("WIZ_PAGE_SIZE", 100)
    with requests.Session() as session:
        retries = Retry(
            total=4, backoff_factor=1, status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods={"POST"}, respect_retry_after_header=True,
        )
        session.mount("https://", HTTPAdapter(max_retries=retries))
        token = get_access_token(session)
        synced_at = datetime.now(timezone.utc)
        accounts: dict[str, str] = {}
        counts: Counter[str] = Counter()
        cicd_reason = cicd_unavailable_reason(session, token)
        LOG.warning(cicd_reason)

        with psycopg.connect(
            host=required_env("DB_HOST"),
            port=positive_int("DB_PORT", 5432),
            dbname=required_env("DB_NAME"),
            user=required_env("DB_USER"),
            password=required_env("DB_PASSWORD"),
            connect_timeout=10,
        ) as connection:
            connection.execute(SCHEMA_SQL)
            connection.commit()
            with connection.transaction():
                for source, query, batch_size in (
                    ("issuesV2", ISSUES_QUERY, page_size),
                    ("vulnerabilityFindings", VULNERABILITIES_QUERY, 500),
                    ("postureIssues", POSTURE_QUERY, page_size),
                ):
                    processed = 0
                    for resolved_after in (None, synced_at - timedelta(days=90)):
                        filters = finding_filters(source, resolved_after)
                        LOG.info("%s: collecting with filters %s", source, filters)
                        for nodes in pages(session, token, source, query, batch_size, filters):
                            rows = [normalize_finding(node, source, accounts, synced_at) for node in nodes]
                            with connection.cursor() as cursor_db:
                                if source == "issuesV2":
                                    cursor_db.executemany(UPSERT_ISSUE, [normalize_issue(node) for node in nodes])
                                cursor_db.executemany(UPSERT_ACTIVE, rows)
                                if source == "vulnerabilityFindings":
                                    cursor_db.executemany(
                                        UPSERT_VULNERABILITY,
                                        [normalize_vulnerability(node) for node in nodes],
                                    )
                            counts.update(row["category"] for row in rows)
                            processed += len(rows)
                            if processed and processed % 5000 == 0:
                                LOG.info("%s: processed %d records", source, processed)
                    connection.execute(
                        "UPDATE wiz_active_issues SET is_active = FALSE "
                        "WHERE source = %s AND synced_at <> %s AND is_active",
                        (source, synced_at),
                    )
                    record_coverage(
                        connection, CATEGORIES[source], True,
                        f"Collected {processed} records (active and last 90 days resolved).",
                    )
                    LOG.info("%s collection completed: %d records", source, processed)
                record_coverage(connection, "CI/CD Scans", False, cicd_reason)
                connection.execute(INSERT_SNAPSHOTS, (datetime.now(timezone.utc),))
    return counts


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    interval = positive_int("SYNC_INTERVAL_SECONDS", 900)
    while True:
        try:
            counts = sync_once()
            LOG.info("Wiz sync completed; categories populated: %s; CI/CD unavailable", dict(counts))
            LOG.info(
                "Wiz vulnerability sync completed; processed %d findings with CVE/package metadata",
                counts["Vulnerability Management"],
            )
        except (requests.RequestException, psycopg.Error, RuntimeError) as exc:
            LOG.exception("Wiz sync failed: %s", exc)
        time.sleep(interval)


if __name__ == "__main__":
    main()
