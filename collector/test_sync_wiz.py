import json
import os
import re
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch
from uuid import uuid4

from psycopg import sql

import sync_wiz as sync


class CategoryTests(unittest.TestCase):
    def setUp(self):
        self.timestamp = datetime.now(timezone.utc)
        self.asset = {
            "id": "resource-1", "name": "server", "type": "VIRTUAL_MACHINE",
            "cloudPlatform": "AWS", "subscriptionExternalId": "account-1",
            "subscriptionName": "Production",
        }

    def test_risk_and_posture_use_issue_type_not_rule_name_keywords(self):
        issue = {
            "id": "same-id", "type": "TOXIC_COMBINATION", "status": "OPEN",
            "severity": "CRITICAL", "entitySnapshot": self.asset,
            "sourceRules": [{"name": "Vulnerability on an exposed resource"}],
        }
        risk = sync.normalize_finding(issue, "issuesV2", {}, self.timestamp)
        self.assertEqual(risk["category"], "Risk Issues")
        self.assertEqual(risk["subscription_name"], "Production")
        issue["type"] = "CLOUD_CONFIGURATION"
        posture = sync.normalize_finding(issue, "issuesV2", {}, self.timestamp)
        self.assertEqual(posture["category"], "Posture Issues")

    def test_vulnerabilities_are_namespaced_and_keep_actual_severity(self):
        issue = {
            "id": "same-id", "status": "IN_PROGRESS", "severity": "MEDIUM",
            "name": "CVE-example", "firstDetectedAt": "2026-11-16T00:00:00Z",
            "vulnerableAsset": self.asset,
        }
        row = sync.normalize_finding(issue, "vulnerabilityFindings", {}, self.timestamp)
        self.assertEqual(row["category"], "Vulnerability Management")
        self.assertEqual(row["id"], "vulnerabilityFindings:same-id")
        self.assertEqual(row["severity"], "MEDIUM")
        self.assertTrue(row["is_active"])
        self.assertEqual(row["rule_name"], "CVE-example")

    def test_posture_environment_uses_account_lookup_and_resolved_is_inactive(self):
        issue = {
            "id": "p1", "status": "RESOLVED", "severity": "HIGH",
            "policy": {"name": "Policy"},
            "groupEntity": {"entity": {
                "id": "r1", "name": "server", "type": "VIRTUAL_MACHINE",
                "properties": {"subscriptionExternalId": "a1", "cloudPlatform": "AWS"},
            }},
        }
        row = sync.normalize_finding(issue, "postureIssues", {"a1": "Staging"}, self.timestamp)
        self.assertEqual(row["category"], "Posture Issues")
        self.assertEqual(row["subscription_name"], "Staging")
        self.assertFalse(row["is_active"])

    def test_resolved_findings_keep_account_and_resolution_metadata(self):
        resolved_at = "2026-11-17T12:00:00Z"
        issue = {
            "id": "v1", "status": "RESOLVED", "severity": "HIGH",
            "vulnerableAsset": self.asset, "resolvedAt": resolved_at,
        }
        row = sync.normalize_finding(issue, "vulnerabilityFindings", {}, self.timestamp)
        metadata = sync.normalize_vulnerability(issue)
        for value in (row, metadata):
            self.assertEqual(value["subscription_external_id"], "account-1")
            self.assertEqual(value["resolved_at"], resolved_at)
        self.assertFalse(row["is_active"])
        issue["status"] = "OPEN"
        self.assertIsNone(sync.normalize_finding(
            issue, "vulnerabilityFindings", {}, self.timestamp
        )["resolved_at"])
        self.assertIsNone(sync.normalize_vulnerability(issue)["resolved_at"])

    @patch.object(sync, "graphql")
    def test_history_filters_are_passed_to_every_pagination_request(self, graphql):
        graphql.side_effect = [
            {"issuesV2": {"nodes": [], "pageInfo": {"hasNextPage": True, "endCursor": "next"}}},
            {"issuesV2": {"nodes": [], "pageInfo": {"hasNextPage": False}}},
        ]
        filters = sync.finding_filters("issuesV2", self.timestamp - timedelta(days=90))
        list(sync.pages(MagicMock(), "token", "issuesV2", sync.ISSUES_QUERY, 100, filters))
        self.assertEqual(
            [call.args[3]["filterBy"] for call in graphql.call_args_list],
            [filters, filters],
        )
        self.assertEqual(graphql.call_args_list[1].args[3]["after"], "next")

    @patch.object(sync, "cicd_unavailable_reason", return_value="CI/CD unavailable")
    @patch.object(sync, "get_access_token", return_value="token")
    @patch.object(sync, "required_env", return_value="configured")
    @patch.object(sync.psycopg, "connect")
    @patch.object(sync, "pages", return_value=iter(()))
    def test_sync_collects_active_and_bounded_resolved_history_for_each_source(self, pages, *_):
        before = datetime.now(timezone.utc) - timedelta(days=90)
        sync.sync_once()
        after = datetime.now(timezone.utc) - timedelta(days=90)
        self.assertEqual(len(pages.call_args_list), 6)
        for source in ("issuesV2", "vulnerabilityFindings", "postureIssues"):
            filters = [call.args[5] for call in pages.call_args_list if call.args[2] == source]
            active, resolved = filters
            self.assertNotIn("resolvedAt", active)
            self.assertEqual(
                active["status"], {"equals": ["OPEN", "IN_PROGRESS"]}
                if source == "postureIssues" else ["OPEN", "IN_PROGRESS"],
            )
            self.assertEqual(
                resolved["status"], {"equals": ["RESOLVED"]}
                if source == "postureIssues" else ["RESOLVED"],
            )
            cutoff = datetime.fromisoformat(resolved["resolvedAt"]["after"])
            self.assertLessEqual(before, cutoff)
            self.assertLessEqual(cutoff, after)
            if source == "vulnerabilityFindings":
                self.assertEqual(active["cloudPlatforms"], ["AWS"])
                self.assertEqual(resolved["severity"], ["CRITICAL", "HIGH", "MEDIUM", "LOW"])

    def test_unknown_issue_type_is_not_silently_misclassified(self):
        with self.assertRaisesRegex(RuntimeError, "Unmapped Wiz issue type"):
            sync.normalize_finding(
                {"id": "x", "type": "FUTURE_TYPE"}, "issuesV2", {}, self.timestamp
            )

    @patch.object(sync, "graphql")
    def test_repeated_pagination_cursor_fails(self, graphql):
        graphql.return_value = {"issuesV2": {
            "nodes": [{"id": "x"}],
            "pageInfo": {"hasNextPage": True, "endCursor": "repeated"},
        }}
        with self.assertRaisesRegex(RuntimeError, "repeated cursor"):
            list(sync.pages(MagicMock(), "token", "issuesV2", "query", 100))

    @patch.object(sync, "graphql")
    def test_missing_page_completion_flag_is_not_success(self, graphql):
        graphql.return_value = {"issuesV2": {"nodes": [], "pageInfo": {}}}
        with self.assertRaisesRegex(RuntimeError, "invalid issuesV2 page"):
            list(sync.pages(MagicMock(), "token", "issuesV2", "query", 100))

    @patch.object(sync, "graphql")
    def test_cicd_denial_is_explicit_but_other_graphql_errors_fail(self, graphql):
        graphql.side_effect = sync.GraphQLError([
            {"extensions": {"code": "UNAUTHORIZED"}, "message": "access denied"}
        ])
        self.assertIn("read:security_scans", sync.cicd_unavailable_reason(MagicMock(), "token"))
        graphql.side_effect = sync.GraphQLError([
            {"extensions": {"code": "INTERNAL_SERVER_ERROR"}, "message": "internal"}
        ])
        with self.assertRaises(sync.GraphQLError):
            sync.cicd_unavailable_reason(MagicMock(), "token")

    @patch.object(sync, "required_env", return_value="configured")
    @patch.object(sync, "cicd_unavailable_reason", return_value="CI/CD unavailable")
    @patch.object(sync, "get_access_token", return_value="token")
    @patch.object(sync.psycopg, "connect")
    @patch.object(sync, "pages")
    def test_failed_collection_does_not_publish_snapshot(self, pages, connect, *_):
        connection = connect.return_value.__enter__.return_value

        def source_pages(session, token, source, query, page_size, filters):
            if source == "vulnerabilityFindings" and filters["status"] == ["RESOLVED"]:
                raise RuntimeError("API failed halfway")
            return iter([[]])

        pages.side_effect = source_pages
        with self.assertRaisesRegex(RuntimeError, "API failed halfway"):
            sync.sync_once()
        self.assertFalse(any(
            call.args[0] == sync.INSERT_SNAPSHOTS for call in connection.execute.call_args_list
        ))
        transaction = connection.transaction.return_value
        self.assertIs(transaction.__exit__.call_args.args[0], RuntimeError)


class VulnerabilityTests(unittest.TestCase):
    def test_artifact_groups_classify_packages_without_guessing_from_asset_or_title(self):
        for group, expected in (
            ("OS_PACKAGE", "OS Package"), ("CODE_LIBRARY", "Application Library"),
            ("HOSTED_TECHNOLOGY", "Hosted Technology"), ("FUTURE_GROUP", "FUTURE_GROUP"),
            ("UNKNOWN", "Unknown"), (None, "Unknown"),
        ):
            with self.subTest(group=group):
                row = sync.normalize_vulnerability({
                    "id": "v1", "artifactType": {"group": group},
                    "name": "OS package", "vulnerableAsset": {"type": "CONTAINER_IMAGE"},
                })
                self.assertEqual(row["vuln_type"], expected)
        self.assertEqual(sync.normalize_vulnerability({"id": "v2"})["vuln_type"], "Unknown")

    def test_cve_package_mapping_uses_nvd_score_and_separates_kev_from_public_exploit(self):
        row = sync.normalize_vulnerability({
            "id": "finding-1", "vulnerabilityExternalId": "CVE-2025-12345",
            "nvdScore": 8.8, "score": 9.9, "CVSSSeverity": "HIGH",
            "detailedName": "openssl", "version": "1.0", "fixedVersion": "1.1",
            "locationPath": "/usr/lib", "hasExploit": True, "hasCisaKevExploit": False,
        })
        self.assertEqual(row["finding_id"], "vulnerabilityFindings:finding-1")
        self.assertEqual(row["cve_id"], "CVE-2025-12345")
        self.assertEqual(row["cvss_score"], 8.8)
        self.assertEqual(row["cvss_severity"], "HIGH")
        self.assertEqual(row["package_name"], "openssl")
        self.assertEqual(row["installed_version"], "1.0")
        self.assertEqual(row["fixed_version"], "1.1")
        self.assertTrue(row["exploit_available"])
        self.assertFalse(row["known_exploited"])

    def test_non_cve_advisories_and_missing_metadata_are_not_fabricated(self):
        row = sync.normalize_vulnerability({
            "id": "eol-1", "vulnerabilityExternalId": "EOL-CLOUD-SERVICE", "score": 0,
        })
        self.assertEqual(row["vulnerability_id"], "EOL-CLOUD-SERVICE")
        self.assertIsNone(row["cve_id"])
        self.assertIsNone(row["cvss_score"])
        self.assertIsNone(row["known_exploited"])
        self.assertIsNone(row["fixed_version"])


@unittest.skipUnless(os.environ.get("DB_HOST"), "Requires the Compose PostgreSQL environment")
class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.connection = sync.psycopg.connect(
            host=sync.required_env("DB_HOST"),
            port=sync.positive_int("DB_PORT", 5432),
            dbname=sync.required_env("DB_NAME"),
            user=sync.required_env("DB_USER"),
            password=sync.required_env("DB_PASSWORD"),
            connect_timeout=10,
        )
        self.addCleanup(self.connection.close)
        self.connection.execute("""
            CREATE TEMP TABLE wiz_active_issues (
                subscription_name TEXT, cloud_platform TEXT, category TEXT,
                severity TEXT, status TEXT, is_active BOOLEAN, id TEXT
            );
            CREATE TEMP TABLE wiz_vulnerabilities (finding_id TEXT, vuln_type TEXT);
            CREATE TEMP TABLE wiz_collection_status (category TEXT, available BOOLEAN);
            CREATE TEMP TABLE wiz_snapshots (
                captured_at TIMESTAMPTZ, subscription_name TEXT, cloud_platform TEXT,
                category TEXT, severity TEXT, issue_count BIGINT,
                metric_type TEXT, vuln_type TEXT
            );
            INSERT INTO wiz_collection_status VALUES
                ('Risk Issues', TRUE), ('Vulnerability Management', TRUE),
                ('Posture Issues', TRUE), ('CI/CD Scans', FALSE);
            INSERT INTO wiz_active_issues (
                subscription_name, cloud_platform, category, severity, status, is_active
            ) VALUES
                ('Production','AWS','Risk Issues','CRITICAL','OPEN',TRUE),
                ('Production','AWS','Vulnerability Management','MEDIUM','OPEN',TRUE),
                ('Production','AWS','Vulnerability Management','MEDIUM','OPEN',TRUE),
                ('Production','AWS','Risk Issues','CRITICAL','RESOLVED',FALSE),
                ('Staging','AWS','Risk Issues','HIGH','OPEN',FALSE),
                ('Other cloud','AZURE','Risk Issues','CRITICAL','OPEN',TRUE),
                ('Production','AWS','CI/CD Scans','HIGH','OPEN',TRUE);
        """)
        self.timestamp = datetime.now(timezone.utc)

    def test_snapshots_record_zeros_but_not_unavailable_sources_or_other_clouds(self):
        self.connection.execute(sync.INSERT_SNAPSHOTS, (self.timestamp,))
        rows = self.connection.execute(
            "SELECT subscription_name, category, severity, issue_count FROM wiz_snapshots"
        ).fetchall()
        values = {(env, category, severity): count for env, category, severity, count in rows}
        self.assertEqual(values["Production", "Risk Issues", "CRITICAL"], 1)
        self.assertEqual(values["Production", "Vulnerability Management", "MEDIUM"], 2)
        self.assertEqual(values["Staging", "Risk Issues", "HIGH"], 0)
        self.assertEqual(values["Production", "Posture Issues", "CRITICAL"], 0)
        self.assertFalse(any(category == "CI/CD Scans" for _, category, _, _ in rows))
        self.assertFalse(any(env == "Other cloud" for env, _, _, _ in rows))

    def test_resolved_findings_drop_to_zero_without_rewriting_history(self):
        self.connection.execute(sync.INSERT_SNAPSHOTS, (self.timestamp,))
        self.connection.execute("UPDATE wiz_active_issues SET is_active = FALSE")
        self.connection.execute(sync.INSERT_SNAPSHOTS, (self.timestamp + timedelta(minutes=15),))
        history = self.connection.execute("""
            SELECT SUM(issue_count) FROM wiz_snapshots
            GROUP BY captured_at ORDER BY captured_at
        """).fetchall()
        self.assertEqual(history, [(3,), (0,)])

    def test_typed_snapshots_preserve_category_totals_and_record_real_zeros(self):
        self.connection.execute("""
            UPDATE wiz_active_issues SET id = 'os'
                WHERE category = 'Vulnerability Management';
            INSERT INTO wiz_vulnerabilities VALUES ('os', 'OS Package');
        """)
        self.connection.execute(sync.INSERT_SNAPSHOTS, (self.timestamp,))
        self.assertEqual(self.connection.execute("""
            SELECT SUM(issue_count) FROM wiz_snapshots
            WHERE metric_type = 'VULNERABILITY'
        """).fetchone(), (2,))
        self.assertEqual(self.connection.execute("""
            SELECT issue_count FROM wiz_snapshots
            WHERE metric_type = 'VULNERABILITY' AND subscription_name = 'Staging'
                AND severity = 'MEDIUM' AND vuln_type = 'OS Package'
        """).fetchone(), (0,))
        self.connection.execute("UPDATE wiz_active_issues SET is_active = FALSE")
        self.connection.execute(sync.INSERT_SNAPSHOTS, (self.timestamp + timedelta(minutes=15),))
        self.assertEqual(self.connection.execute("""
            SELECT SUM(issue_count) FROM wiz_snapshots
            WHERE metric_type = 'VULNERABILITY'
            GROUP BY captured_at ORDER BY captured_at
        """).fetchall(), [(2,), (0,)])


@unittest.skipUnless(os.environ.get("DB_HOST"), "Requires the Compose PostgreSQL environment")
class VulnerabilityDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.connection = sync.psycopg.connect(
            host=sync.required_env("DB_HOST"),
            port=sync.positive_int("DB_PORT", 5432),
            dbname=sync.required_env("DB_NAME"),
            user=sync.required_env("DB_USER"),
            password=sync.required_env("DB_PASSWORD"),
            connect_timeout=10,
        )
        self.addCleanup(self.connection.close)
        schema = sql.Identifier("wiz_test_" + uuid4().hex)
        self.connection.execute(sql.SQL("CREATE SCHEMA {}").format(schema))
        self.connection.execute(sql.SQL("SET LOCAL search_path TO {}").format(schema))
        self.connection.execute(sync.SCHEMA_SQL)
        self.connection.execute(sync.SCHEMA_SQL)
        self.timestamp = datetime.now(timezone.utc)
        dashboard_path = (
            Path(__file__).resolve().parent.parent
            / "grafana" / "provisioning" / "dashboards" / "wiz-vulnerability-management.json"
        )
        self.dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))

    def insert_finding(
        self, finding_id, cve, score, kev, public_exploit, days_open=10,
        group="OS_PACKAGE", environment="Production",
        account_id=None, status="OPEN", resolved_at=None, severity="HIGH",
        cloud_platform="AWS",
    ):
        finding = {
            "id": finding_id, "vulnerabilityExternalId": cve, "nvdScore": score,
            "CVSSSeverity": "HIGH", "detailedName": "openssl", "version": "1.0",
            "fixedVersion": "1.1", "hasExploit": public_exploit, "hasCisaKevExploit": kev,
            "status": status, "severity": severity, "resolvedAt": resolved_at,
            "artifactType": {"group": group},
            "firstDetectedAt": (self.timestamp - timedelta(days=days_open)).isoformat(),
            "vulnerableAsset": {
                "id": "server-1", "name": "server", "type": "VIRTUAL_MACHINE",
                "cloudPlatform": cloud_platform, "subscriptionName": environment,
                "subscriptionExternalId": account_id,
            },
        }
        self.connection.execute(
            sync.UPSERT_ACTIVE,
            sync.normalize_finding(finding, "vulnerabilityFindings", {}, self.timestamp),
        )
        self.connection.execute(sync.UPSERT_VULNERABILITY, sync.normalize_vulnerability(finding))

    def query_panel(self, panel_id):
        panel = next(panel for panel in self.dashboard["panels"] if panel["id"] == panel_id)
        query = panel["targets"][0]["rawSql"]
        query = query.replace("${environment:sqlstring}", "'Production'")
        query = query.replace("${severity:sqlstring}", "'HIGH'")
        return self.connection.execute(query).fetchall()

    def test_annotation_events_survive_schema_reapplication_and_are_readable_by_grafana(self):
        event = self.connection.execute("""
            INSERT INTO wiz_annotations (title, description, tags, environment)
            VALUES ('Deployment', 'Release deployed', 'deployment,production', 'Production')
            RETURNING id, event_time
        """).fetchone()
        self.assertIsInstance(event[0], int)
        self.assertIsInstance(event[1], datetime)
        self.connection.execute(sync.SCHEMA_SQL)
        self.connection.execute(sync.SCHEMA_SQL)
        self.assertEqual(self.connection.execute("""
            SELECT id, event_time, title, description, tags, environment FROM wiz_annotations
        """).fetchall(), [
            (*event, "Deployment", "Release deployed", "deployment,production", "Production"),
        ])
        self.assertEqual(self.connection.execute("""
            SELECT has_table_privilege('grafana_ro', 'wiz_annotations', 'SELECT')
        """).fetchone(), (True,))

    def test_dashboard_annotations_filter_event_times_and_severities(self):
        recent_resolution = (self.timestamp - timedelta(days=1)).isoformat()
        for finding_id, options in (
            ("critical", {"severity": "CRITICAL"}),
            ("old-critical", {"severity": "CRITICAL", "days_open": 60}),
            ("resolved-high", {"status": "RESOLVED", "resolved_at": recent_resolution,
                               "days_open": 60}),
            ("resolved-low", {"status": "RESOLVED", "resolved_at": recent_resolution,
                              "severity": "LOW"}),
            ("missing-resolution", {"status": "RESOLVED"}),
        ):
            self.insert_finding(finding_id, "CVE-test", 7.5, False, False, **options)
        self.connection.execute("""
            UPDATE wiz_active_issues SET rule_name = 'CVE-test';
            INSERT INTO wiz_annotations (title, description, tags) VALUES
                ('Deployment', 'Release deployed', 'deployment,production');
            INSERT INTO wiz_annotations (event_time, title) VALUES
                (NOW() - INTERVAL '60 days', 'Old deployment');
        """)
        for name in ("wiz-security-overview", "eu-us-prod"):
            path = (
                Path(__file__).resolve().parent.parent / "grafana" / "provisioning"
                / "dashboards" / f"{name}.json"
            )
            annotations = json.loads(path.read_text(encoding="utf-8"))["annotations"]["list"]
            for annotation, title, text, tags in zip(
                annotations,
                ("CRITICAL: CVE-test", "RESOLVED: CVE-test", "Deployment"),
                ("Production | server", "Production | server", "Release deployed"),
                ("critical,wiz", "resolved,wiz", "deployment,production"),
                strict=True,
            ):
                with self.subTest(dashboard=name, annotation=annotation["name"]):
                    query = re.sub(
                        r"\$__timeFilter\((\w+)\)",
                        r"\1 BETWEEN NOW() - INTERVAL '30 days' AND NOW()",
                        annotation["target"]["rawSql"],
                    )
                    cursor = self.connection.execute(query)
                    self.assertEqual(
                        [column.name for column in cursor.description],
                        ["time", "title", "text", "tags"],
                    )
                    rows = cursor.fetchall()
                    self.assertEqual(len(rows), 1)
                    self.assertIsInstance(rows[0][0], datetime)
                    self.assertEqual(rows[0][1:], (title, text, tags))

    def test_dashboard_deduplicates_packages_and_kev_cves_and_ranks_cvss(self):
        self.insert_finding("one", "CVE-2025-11111", 8.8, True, True)
        self.insert_finding("two", "CVE-2025-22222", 7.5, False, True, days_open=20)
        self.insert_finding("three", "CVE-2025-11111", 8.8, True, True)
        self.assertEqual(self.query_panel(1), [(1,)])
        self.assertAlmostEqual(self.query_panel(2)[0][0], 40 / 3, places=3)
        self.assertEqual(self.query_panel(3), [(1,)])
        self.assertEqual([row[2] for row in self.query_panel(6)], [8.8, 8.8, 7.5])
        self.connection.execute(
            "UPDATE wiz_active_issues SET is_active = FALSE WHERE id = %s",
            ("vulnerabilityFindings:two",),
        )
        self.assertEqual(len(self.query_panel(6)), 2)

    def test_upsert_refreshes_metadata_without_duplicate_findings(self):
        self.insert_finding("one", "CVE-2025-11111", 7.5, False, False)
        self.insert_finding("one", "CVE-2025-11111", 9.0, True, True)
        row = self.connection.execute(
            "SELECT COUNT(*), MAX(cvss_score), BOOL_OR(known_exploited) FROM wiz_vulnerabilities"
        ).fetchone()
        self.assertEqual(row, (1, 9.0, True))

    def test_simple_dashboard_filters_types_environments_and_keeps_snapshot_history(self):
        self.insert_finding("one", "CVE-2025-11111", 7.5, False, False)
        self.insert_finding(
            "two", "CVE-2025-22222", 8.8, False, False,
            group="CODE_LIBRARY", environment="Team's Staging",
        )
        self.insert_finding("three", "CVE-2025-33333", 7.5, False, False)
        self.connection.execute("""
            UPDATE wiz_active_issues SET status = 'IN_PROGRESS'
                WHERE id = 'vulnerabilityFindings:three';
            INSERT INTO wiz_collection_status VALUES
                ('Vulnerability Management', TRUE, NOW(), NOW(), 'test');
        """)
        self.connection.execute(sync.INSERT_SNAPSHOTS, (self.timestamp,))
        dashboard_path = (
            Path(__file__).resolve().parent.parent / "grafana" / "provisioning"
            / "dashboards" / "wiz-vulnerabilities-simple.json"
        )
        dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
        for environments, types, expected in (
            ("'Production','Team''s Staging'", "'OS Package','Application Library','Unknown'", 2),
            ("'Production'", "'OS Package'", 1),
            ("'Team''s Staging'", "'Application Library'", 1),
            ("'Production'", "'Application Library'", 0),
        ):
            with self.subTest(environments=environments, types=types):
                results = []
                for panel in dashboard["panels"]:
                    query = panel["targets"][0]["rawSql"]
                    query = query.replace("${environment:sqlstring}", environments)
                    query = query.replace("${vuln_type:sqlstring}", types)
                    query = query.replace("$__timeFilter(recorded_at)", "recorded_at > NOW() - INTERVAL '1 day'")
                    results.append(self.connection.execute(query).fetchall())
                self.assertEqual(sum(row[2] for row in results[0]), expected)
                self.assertEqual(sum(row[2] for row in results[1]), expected)
                self.assertEqual(sum(row[1] for row in results[2]), expected)
                self.assertEqual(len(results[3]), expected)
                self.assertTrue(all(row[3] == "HIGH" for row in results[3]))
        before = self.connection.execute(
            "SELECT captured_at, category, severity, SUM(issue_count) FROM wiz_snapshots GROUP BY 1,2,3 ORDER BY 1,2,3"
        ).fetchall()
        self.connection.execute(sync.SCHEMA_SQL)
        after = self.connection.execute(
            "SELECT recorded_at, category, severity, SUM(issue_count) FROM wiz_snapshots GROUP BY 1,2,3 ORDER BY 1,2,3"
        ).fetchall()
        self.assertEqual(before, after)

    def test_migration_labels_old_history_unknown_without_inventing_type_breakdowns(self):
        self.connection.execute("""
            INSERT INTO wiz_snapshots (
                captured_at, subscription_name, cloud_platform, category, severity, issue_count
            ) VALUES (NOW() - INTERVAL '1 day', 'Production', 'AWS',
                'Vulnerability Management', 'HIGH', 123);
        """)
        self.connection.execute(sync.SCHEMA_SQL)
        self.connection.execute(sync.SCHEMA_SQL)
        self.assertEqual(self.connection.execute("""
            SELECT issue_count, metric_type, vuln_type, captured_at = recorded_at
            FROM wiz_snapshots
        """).fetchall(), [(123, "VULNERABILITY", "Unknown", True)])

    def test_resolution_history_is_preserved_and_reopened_findings_clear_resolution(self):
        resolved_at = self.timestamp - timedelta(days=100)
        for resolution in (resolved_at.isoformat(), None):
            self.insert_finding(
                "resolved", "CVE-2025-11111", 7.5, False, False,
                account_id="297157437385", status="RESOLVED", resolved_at=resolution,
            )
        self.connection.execute(sync.SCHEMA_SQL)
        self.connection.execute(sync.SCHEMA_SQL)
        self.assertEqual(self.connection.execute("""
            SELECT a.status, a.is_active, a.subscription_external_id, a.resolved_at,
                v.subscription_external_id, v.resolved_at
            FROM wiz_active_issues a JOIN wiz_vulnerabilities v ON v.finding_id = a.id
        """).fetchall(), [
            ("RESOLVED", False, "297157437385", resolved_at, "297157437385", resolved_at),
        ])
        self.insert_finding(
            "resolved", "CVE-2025-11111", 7.5, False, False,
            account_id="297157437385", status="IN_PROGRESS",
        )
        self.assertEqual(self.connection.execute("""
            SELECT a.status, a.is_active, a.resolved_at, v.resolved_at
            FROM wiz_active_issues a JOIN wiz_vulnerabilities v ON v.finding_id = a.id
        """).fetchall(), [("IN_PROGRESS", True, None, None)])

    def test_history_migration_backfills_stored_api_metadata_without_fabricating_dates(self):
        resolution = self.timestamp - timedelta(days=2)
        self.insert_finding(
            "legacy", "CVE-2025-11111", 7.5, False, False,
            account_id="606889819964", status="RESOLVED", resolved_at=resolution.isoformat(),
        )
        self.connection.execute("""
            UPDATE wiz_active_issues SET subscription_external_id = NULL, resolved_at = NULL;
            UPDATE wiz_vulnerabilities SET subscription_external_id = NULL, resolved_at = NULL;
        """)
        self.connection.execute(sync.SCHEMA_SQL)
        self.assertEqual(self.connection.execute("""
            SELECT a.subscription_external_id, a.resolved_at,
                v.subscription_external_id, v.resolved_at
            FROM wiz_active_issues a JOIN wiz_vulnerabilities v ON v.finding_id = a.id
        """).fetchall(), [("606889819964", resolution, "606889819964", resolution)])
        self.insert_finding(
            "missing-date", "CVE-2025-22222", 7.5, False, False, status="RESOLVED",
        )
        self.connection.execute(sync.SCHEMA_SQL)
        self.assertIsNone(self.connection.execute("""
            SELECT resolved_at FROM wiz_active_issues
            WHERE id = 'vulnerabilityFindings:missing-date'
        """).fetchone()[0])

    def test_production_dashboard_enforces_accounts_statuses_and_event_time_semantics(self):
        us = "297157437385"
        eu = "606889819964"
        recent_resolution = (self.timestamp - timedelta(days=1)).isoformat()
        old_resolution = (self.timestamp - timedelta(days=60)).isoformat()
        for finding_id, options in (
            ("us-open", {"account_id": us, "severity": "CRITICAL"}),
            ("eu-progress", {"account_id": eu, "status": "IN_PROGRESS"}),
            ("us-low", {"account_id": us, "severity": "LOW"}),
            ("eu-name-fallback", {"environment": "mitg-pillcamgeniuseu-prod-mdt"}),
            ("recent-resolution", {"account_id": eu, "status": "RESOLVED",
                                   "resolved_at": recent_resolution, "days_open": 100}),
            ("old-resolution", {"account_id": us, "status": "RESOLVED",
                                "resolved_at": old_resolution, "days_open": 100}),
            ("opened-and-resolved", {"account_id": us, "status": "RESOLVED",
                                    "resolved_at": recent_resolution}),
            ("old-open", {"account_id": us, "days_open": 100}),
            ("outside", {"account_id": "111111111111"}),
            ("outside-resolved", {"account_id": "111111111111", "status": "RESOLVED",
                                  "resolved_at": recent_resolution}),
            ("other-cloud", {"account_id": us, "cloud_platform": "AZURE"}),
            ("rejected", {"account_id": us, "status": "REJECTED"}),
            ("stale-open", {"account_id": us}),
        ):
            self.insert_finding(finding_id, "CVE-2025-11111", 7.5, False, False, **options)
        self.connection.execute("""
            UPDATE wiz_active_issues SET is_active = FALSE
            WHERE id = 'vulnerabilityFindings:stale-open'
        """)
        dashboard_path = (
            Path(__file__).resolve().parent.parent / "grafana" / "provisioning"
            / "dashboards" / "eu-us-prod.json"
        )
        dashboard = json.loads(dashboard_path.read_text(encoding="utf-8"))
        start = (self.timestamp - timedelta(days=30)).isoformat()
        end = self.timestamp.isoformat()
        results = {}
        for panel in dashboard["panels"]:
            query = panel["targets"][0]["rawSql"]
            for column in ("created_at", "resolved_at", "a.created_at", "a.resolved_at"):
                query = query.replace(
                    f"$__timeFilter({column})", f"{column} BETWEEN '{start}' AND '{end}'",
                )
            results[panel["id"]] = self.connection.execute(query).fetchall()
        self.assertEqual([results[i][0][0] for i in (1, 2, 3, 4)], [1, 2, 2, 6])
        trends = {row[1]: row[2] for row in results[5]}
        self.assertEqual(trends, {"Opened": 6, "Resolved": 2})
        self.assertEqual(sum(row[1] for row in results[6]), 3)
        self.assertEqual(sum(row[2] for row in results[6]), 3)
        self.assertEqual(len(results[7]), 2)
        self.assertTrue(all(row[0].isoformat() == recent_resolution for row in results[7]))
        self.assertEqual(len(results[8]), 4)
        self.assertEqual([row[2] for row in results[8]], ["CRITICAL", "HIGH", "HIGH", "LOW"])
        self.assertEqual({row[3] for row in results[8]}, {"OPEN", "IN_PROGRESS"})


if __name__ == "__main__":
    unittest.main()
