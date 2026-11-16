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
