import os
import unittest
from unittest.mock import MagicMock, patch

import requests
from fastapi import HTTPException

from wiz_scans import ScanTarget, WizClient


ACCOUNT = "123456789012"
ARN = f"arn:aws:ec2:us-east-1:{ACCOUNT}:instance/i-0123456789abcdef0"
TARGET = ScanTarget(
    id="vm-one", name="example-node", resource_id="i-0123456789abcdef0",
    arn=ARN, environment=ACCOUNT, region="us-east-1",
)


def response(payload):
    value = MagicMock()
    value.status_code = 200
    value.ok = True
    value.json.return_value = payload
    return value


def inventory(nodes, next_page=False, cursor=None):
    return {"data": {"cloudResources": {
        "nodes": nodes, "pageInfo": {"hasNextPage": next_page, "endCursor": cursor},
    }}}


def resource(arn=ARN, status="Active"):
    return {
        "id": TARGET.id, "name": TARGET.name,
        "graphEntity": {"properties": {"providerUniqueId": arn, "status": status}},
    }


@patch.dict(os.environ, {
    "WIZ_API_URL": "https://api.example.test/graphql",
    "WIZ_CLIENT_ID": "test-client",
    "WIZ_CLIENT_SECRET": "test-secret",
})
class WizClientTests(unittest.TestCase):
    def setUp(self):
        self.session = MagicMock(spec=requests.Session)
        self.session.post.return_value = response({"access_token": "private-access-token"})
        self.client = WizClient(self.session)

    def test_inventory_pages_deduplicate_and_exclude_inactive_or_representative_vms(self):
        self.session.post.side_effect = [
            response(inventory([resource()], True, "next")),
            response(inventory([
                resource(),
                resource(status="Deleted"),
                resource(arn="wiz-representative##arn:aws:autoscaling:example"),
            ])),
        ]
        self.assertEqual(self.client.resources(ACCOUNT), [TARGET])
        self.assertEqual(
            self.session.post.call_args.kwargs["json"]["variables"]["after"], "next"
        )

    def test_inventory_does_not_accept_another_aws_account(self):
        self.session.post.return_value = response(
            inventory([resource(arn=ARN.replace(ACCOUNT, "999999999999"))])
        )
        with self.assertRaises(HTTPException) as error:
            self.client.resources(ACCOUNT)
        self.assertEqual(error.exception.status_code, 502)

    def test_repeated_inventory_cursor_stops_pagination(self):
        self.session.post.return_value = response(inventory([resource()], True, "same"))
        with self.assertRaises(HTTPException) as error:
            self.client.resources(ACCOUNT)
        self.assertEqual(error.exception.status_code, 502)
        self.assertIn("repeated", error.exception.detail)

    def test_scan_submits_the_full_arn_and_does_not_return_the_scan_token(self):
        self.session.post.return_value = response({
            "data": {"initiateDiskScanVirtualMachine": {"token": "private-scan-token"}}
        })
        self.assertIsNone(self.client.start_scan(TARGET))
        payload = self.session.post.call_args.kwargs["json"]
        self.assertEqual(payload["variables"], {"input": {"resourceID": ARN}})

    def test_authentication_failure_is_not_misreported_as_missing_scan_permission(self):
        session = MagicMock(spec=requests.Session)
        rejected = response({"error": "invalid_client"})
        rejected.status_code = 401
        rejected.ok = False
        session.post.return_value = rejected
        with self.assertLogs("wiz_scans", level="ERROR"):
            with self.assertRaises(HTTPException) as error:
                WizClient(session)
        self.assertEqual(error.exception.status_code, 502)
        self.assertIn("authentication failed", error.exception.detail)
        self.assertNotIn("create:security_scans", error.exception.detail)

    def test_permission_denied_is_not_reported_as_an_accepted_scan(self):
        self.session.post.return_value = response({
            "errors": [{"message": "Access denied", "extensions": {"code": "UNAUTHORIZED"}}]
        })
        with self.assertLogs("wiz_scans", level="ERROR"):
            with self.assertRaises(HTTPException) as error:
                self.client.start_scan(TARGET)
        self.assertEqual(error.exception.status_code, 403)
        self.assertIn("create:security_scans", error.exception.detail)
        self.assertNotIn("private-", error.exception.detail)

    def test_network_failure_does_not_claim_scan_rejection_or_acceptance(self):
        self.session.post.side_effect = requests.Timeout("private connection details")
        with self.assertLogs("wiz_scans", level="ERROR") as logs:
            with self.assertRaises(HTTPException) as error:
                self.client.start_scan(TARGET)
        self.assertEqual(error.exception.status_code, 502)
        self.assertIn("Check Wiz before retrying", error.exception.detail)
        self.assertNotIn("private connection details", "".join(logs.output))


if __name__ == "__main__":
    unittest.main()
