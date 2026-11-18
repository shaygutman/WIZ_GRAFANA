\getenv grafana_db_password GRAFANA_DB_PASSWORD
\getenv database_name POSTGRES_DB
CREATE ROLE grafana_ro LOGIN PASSWORD :'grafana_db_password';

CREATE TABLE wiz_issues (
    id TEXT PRIMARY KEY,
    severity TEXT,
    status TEXT,
    issue_type TEXT,
    created_at TIMESTAMPTZ,
    resolved_at TIMESTAMPTZ,
    description TEXT,
    entity_id TEXT,
    entity_name TEXT,
    entity_type TEXT,
    raw JSONB NOT NULL,
    synced_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX wiz_issues_severity_idx ON wiz_issues (severity);
CREATE INDEX wiz_issues_status_idx ON wiz_issues (status);
CREATE INDEX wiz_issues_created_at_idx ON wiz_issues (created_at);

CREATE OR REPLACE VIEW wiz_issue_summary AS
SELECT severity, status, COUNT(*) AS issue_count
FROM wiz_issues
GROUP BY severity, status;

CREATE OR REPLACE VIEW wiz_issues_daily AS
SELECT DATE_TRUNC('day', created_at) AS day, severity, COUNT(*) AS issue_count
FROM wiz_issues
WHERE created_at IS NOT NULL
GROUP BY DATE_TRUNC('day', created_at), severity;

GRANT CONNECT ON DATABASE :"database_name" TO grafana_ro;
GRANT USAGE ON SCHEMA public TO grafana_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO grafana_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT ON TABLES TO grafana_ro;

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
