import json
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

import psycopg2
from fastapi import HTTPException
from pydantic import ValidationError

import app
from wiz_scans import ScanTarget


class AnnotationTests(unittest.TestCase):
    @patch.object(app, "WEBHOOK_TOKEN", "test-token")
    def test_api_key_is_required_and_invalid_keys_are_unauthorized(self):
        for token in (None, "", "wrong", "non-ascii-\u00e9"):
            with self.subTest(token=token):
                with self.assertRaises(HTTPException) as error:
                    app.require_api_key(token)
                self.assertEqual(error.exception.status_code, 401)
        app.require_api_key("test-token")

    def test_validation_rejects_oversized_fields_blank_titles_and_ambiguous_times(self):
        for fields in (
            {"title": " "},
            {"title": "x" * 256},
            {"environment": ""},
            {"environment": "x" * 151},
            {"tags": "x" * 101},
            {"description": "invalid\x00text"},
            {"event_time": "2026-11-18T12:00:00"},
            {"event_time": "not-a-timestamp"},
            {"event_time": 1795000000},
            {"unexpected": True},
        ):
            with self.subTest(fields=fields):
                with self.assertRaises(ValidationError):
                    app.AnnotationRequest.model_validate(
                        {"title": "Deployment", "environment": "us-prod"} | fields
                    )

    @patch.object(app.psycopg2, "connect")
    def test_insert_is_parameterized_uses_database_time_and_closes_connection(self, connect):
        connection = connect.return_value
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = (42,)
        title = "Release'; DROP TABLE wiz_annotations; --"
        result = app.create_annotation(
            app.AnnotationRequest(title=title, environment="us-prod")
        )
        self.assertEqual(result.id, 42)
        query, parameters = cursor.execute.call_args.args
        self.assertIn("COALESCE(%s, NOW())", query)
        self.assertNotIn(title, query)
        self.assertEqual(parameters, (None, title, None, "deploy,cicd", "us-prod"))
        connection.__exit__.assert_called_once_with(None, None, None)
        connection.close.assert_called_once()

    @patch.object(app.psycopg2, "connect")
    def test_explicit_timestamp_description_and_tags_are_preserved(self, connect):
        cursor = connect.return_value.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = (43,)
        annotation = app.AnnotationRequest(
            title="Maintenance",
            environment="eu-prod",
            description="Scheduled maintenance",
            tags="maintenance,pillcam-devops",
            event_time="2026-11-18T12:00:00+02:00",
        )
        app.create_annotation(annotation)
        self.assertEqual(
            cursor.execute.call_args.args[1],
            (
                datetime.fromisoformat("2026-11-18T12:00:00+02:00"),
                "Maintenance",
                "Scheduled maintenance",
                "maintenance,pillcam-devops",
                "eu-prod",
            ),
        )

    @patch.object(app.psycopg2, "connect")
    def test_database_errors_return_503_without_exposing_database_details(self, connect):
        connection = connect.return_value
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.execute.side_effect = psycopg2.OperationalError("private connection details")
        with self.assertLogs(app.LOG, level="ERROR") as logs:
            with self.assertRaises(HTTPException) as error:
                app.create_annotation(
                    app.AnnotationRequest(title="Deployment", environment="us-prod")
                )
        self.assertEqual(error.exception.status_code, 503)
        self.assertNotIn("private connection details", error.exception.detail)
        self.assertNotIn("private connection details", "".join(logs.output))
        self.assertIs(
            connection.__exit__.call_args.args[0], psycopg2.OperationalError
        )
        connection.close.assert_called_once()


class ScanRequestTests(unittest.TestCase):
    def test_invalid_targets_types_and_unknown_fields_are_rejected(self):
        for fields in (
            {"environment": " "},
            {"environment": "x" * 151},
            {"resource_id": ""},
            {"resource_id": "invalid\x00resource"},
            {"scan_type": " "},
            {"scan_type": None},
            {"execute": True},
        ):
            with self.subTest(fields=fields):
                with self.assertRaises(ValidationError):
                    app.ScanRequest.model_validate(fields)

    @patch.object(app.psycopg2, "connect")
    def test_scan_audit_preserves_optional_targets_and_never_claims_execution(self, connect):
        connection = connect.return_value
        cursor = connection.cursor.return_value.__enter__.return_value
        cursor.fetchone.return_value = (44,)
        resource = "instance'; DROP TABLE wiz_annotations; --"
        for fields in (
            {},
            {"environment": "PROD", "resource_id": resource, "scan_type": "vulnerability"},
        ):
            with self.subTest(fields=fields):
                result = app.request_scan(app.ScanRequest.model_validate(fields))
                self.assertEqual(result.annotation_id, 44)
                self.assertEqual(result.status, "recorded")
                self.assertEqual(result.execution_mode, "audit_only")
                self.assertIn("No Wiz scan", result.message)
                query, parameters = cursor.execute.call_args.args
                self.assertNotIn(resource, query)
                self.assertIsNone(parameters[0])
                self.assertEqual(parameters[4], fields.get("environment"))
                audit = json.loads(parameters[2])
                self.assertEqual(audit["environment"], fields.get("environment"))
                self.assertEqual(audit["resource_id"], fields.get("resource_id"))
                self.assertEqual(audit["scan_type"], fields.get("scan_type", "full"))
                self.assertEqual(audit["execution_mode"], "audit_only")
                self.assertFalse(audit["scan_started"])
        self.assertEqual(connection.close.call_count, 2)

    @patch.object(
        app.psycopg2, "connect",
        side_effect=psycopg2.OperationalError("private connection details"),
    )
    def test_failed_audit_is_not_accepted(self, connect):
        with self.assertLogs(app.LOG, level="ERROR") as logs:
            with self.assertRaises(HTTPException) as error:
                app.request_scan(app.ScanRequest(environment="PROD"))
        self.assertEqual(error.exception.status_code, 503)
        self.assertNotIn("private connection details", error.exception.detail)
        self.assertNotIn("private connection details", "".join(logs.output))


class RealScanTests(unittest.TestCase):
    def setUp(self):
        self.targets = [
            ScanTarget(
                id=f"vm-{index}", name="example-node", resource_id=f"i-0000000000000000{index}",
                arn=f"arn:aws:ec2:us-east-1:123456789012:instance/i-0000000000000000{index}",
                environment="123456789012", region="us-east-1",
            )
            for index in range(3)
        ]
        self.client = MagicMock()
        self.client.resources.return_value = self.targets
        self.insert = MagicMock(return_value=50)
        self.update = MagicMock()
        replacements = {
            "resolve_scan_environment": MagicMock(
                return_value=app.ScanEnvironment(id="123456789012", name="Production"),
            ),
            "WizClient": MagicMock(return_value=self.client),
            "insert_annotation": self.insert,
            "update_scan_audit": self.update,
        }
        for name, value in replacements.items():
            patcher = patch.object(app, name, value)
            self.addCleanup(patcher.stop)
            patcher.start()

    def test_single_resource_only_submits_the_selected_arn(self):
        result = app.run_scan(app.ScanRequest(
            environment="123456789012", resource_id=self.targets[1].arn,
        ))
        self.client.start_scan.assert_called_once_with(self.targets[1])
        self.assertEqual(result.status, "submitted")
        self.assertEqual(len(result.results), 1)
        self.assertIn("Check Wiz for completion", result.message)
        self.update.assert_called_once_with(50, result)

    def test_environment_scan_submits_all_eligible_targets(self):
        result = app.run_scan(app.ScanRequest(environment="123456789012"))
        self.assertEqual(self.client.start_scan.call_count, 3)
        self.assertEqual([item.status for item in result.results], ["submitted"] * 3)
        self.assertEqual(result.annotation_id, 50)

    def test_denied_permission_returns_403_and_does_not_try_remaining_targets(self):
        self.client.start_scan.side_effect = HTTPException(403, "Missing create:security_scans")
        response = app.run_scan(app.ScanRequest(environment="123456789012"))
        self.assertEqual(response.status_code, 403)
        payload = json.loads(response.body)
        self.assertEqual(payload["status"], "failed")
        self.assertEqual(
            [item["status"] for item in payload["results"]],
            ["failed", "not_attempted", "not_attempted"],
        )
        self.client.start_scan.assert_called_once()
        self.update.assert_called_once()

    def test_partial_batch_failure_reports_accepted_targets_separately(self):
        self.client.start_scan.side_effect = [None, HTTPException(403, "Access denied")]
        response = app.run_scan(app.ScanRequest(environment="123456789012"))
        self.assertEqual(response.status_code, 207)
        payload = json.loads(response.body)
        self.assertEqual(payload["status"], "partial_failure")
        self.assertEqual(
            [item["status"] for item in payload["results"]],
            ["submitted", "failed", "not_attempted"],
        )

    def test_network_error_marks_acceptance_unconfirmed(self):
        self.client.start_scan.side_effect = HTTPException(502, "Check Wiz before retrying")
        response = app.run_scan(app.ScanRequest(environment="123456789012"))
        self.assertEqual(response.status_code, 502)
        self.assertEqual(json.loads(response.body)["status"], "unconfirmed")

    def test_audit_failure_prevents_any_scan_submission(self):
        self.insert.side_effect = HTTPException(503, "Unable to save annotation")
        with self.assertRaises(HTTPException):
            app.run_scan(app.ScanRequest(environment="123456789012"))
        self.client.start_scan.assert_not_called()

    def test_unknown_resource_does_not_become_an_environment_scan(self):
        with self.assertRaises(HTTPException) as error:
            app.run_scan(app.ScanRequest(environment="123456789012", resource_id="missing"))
        self.assertEqual(error.exception.status_code, 404)
        self.client.start_scan.assert_not_called()

    def test_real_scan_requires_explicit_environment_and_supported_scan_type(self):
        for fields in ({}, {"environment": "123456789012", "scan_type": "unsupported"}):
            with self.subTest(fields=fields):
                with self.assertRaises(HTTPException) as error:
                    app.run_scan(app.ScanRequest.model_validate(fields))
                self.assertEqual(error.exception.status_code, 422)
        self.client.start_scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
