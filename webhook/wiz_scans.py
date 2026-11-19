import logging
import os
import re
from typing import Any

import requests
from fastapi import HTTPException
from pydantic import BaseModel


LOG = logging.getLogger("wiz_scans")
EC2_ARN = re.compile(r"arn:aws(?:-[a-z-]+)?:ec2:([a-z0-9-]+):(\d{12}):instance/(i-[a-f0-9]+)")
RESOURCES_QUERY = """
query ScanTargets($after: String, $filterBy: CloudResourceFilters!) {
  cloudResources(first: 100, after: $after, filterBy: $filterBy) {
    nodes { id name graphEntity { properties } }
    pageInfo { hasNextPage endCursor }
  }
}
"""
START_SCAN = """
mutation ManualVMScan($input: InitiateDiskScanVirtualMachineInput!) {
  initiateDiskScanVirtualMachine(input: $input) { token }
}
"""


class ScanTarget(BaseModel):
    id: str
    name: str
    resource_id: str
    arn: str
    environment: str
    region: str


class WizClient:
    def __init__(self, session: requests.Session) -> None:
        self.session = session
        self.api_url = os.environ.get("WIZ_API_URL", "")
        client_id = os.environ.get("WIZ_CLIENT_ID", "")
        client_secret = os.environ.get("WIZ_CLIENT_SECRET", "")
        if not self.api_url or not client_id or not client_secret:
            LOG.error("Wiz scan integration is not configured")
            raise HTTPException(503, "Wiz scan integration is not configured.")
        payload = self._post(
            os.environ.get("WIZ_AUTH_URL", "https://auth.app.wiz.io/oauth/token"),
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": client_secret,
                "audience": os.environ.get("WIZ_AUDIENCE", "wiz-api"),
            },
        )
        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            LOG.error("Wiz authentication returned no access token")
            raise HTTPException(502, "Wiz authentication failed.")
        self._token = token

    def _post(self, url: str, **kwargs: Any) -> dict[str, Any]:
        try:
            response = self.session.post(url, timeout=(10, 60), **kwargs)
        except requests.RequestException as exc:
            LOG.error("Wiz request failed (%s)", type(exc).__name__)
            raise HTTPException(502, "Wiz did not confirm the request. Check Wiz before retrying.") from exc
        if response.status_code in (401, 403):
            LOG.error("Wiz rejected authentication or authorization (HTTP %s)", response.status_code)
            if url != self.api_url:
                raise HTTPException(
                    502, "Wiz authentication failed. Verify the configured service account credentials.",
                )
            raise HTTPException(
                403,
                "Wiz access denied. Manual scans require create:security_scans; "
                "target lookup requires read:resources.",
            )
        if not response.ok:
            LOG.error("Wiz request failed (HTTP %s)", response.status_code)
            raise HTTPException(502, "Wiz did not confirm the request. Check Wiz before retrying.")
        try:
            payload = response.json()
        except ValueError as exc:
            LOG.error("Wiz returned invalid JSON")
            raise HTTPException(502, "Wiz returned an invalid response.") from exc
        if not isinstance(payload, dict):
            raise HTTPException(502, "Wiz returned an invalid response.")
        return payload

    def graphql(self, query: str, variables: dict[str, Any]) -> dict[str, Any]:
        payload = self._post(
            self.api_url,
            headers={"Authorization": f"Bearer {self._token}"},
            json={"query": query, "variables": variables},
        )
        errors = payload.get("errors")
        if errors:
            if not isinstance(errors, list):
                raise HTTPException(502, "Wiz returned invalid GraphQL errors.")
            codes = {
                error["extensions"].get("code")
                for error in errors
                if isinstance(error, dict) and isinstance(error.get("extensions"), dict)
            }
            LOG.error("Wiz GraphQL request failed (codes=%s)", sorted(str(code) for code in codes))
            if codes & {"UNAUTHORIZED", "FORBIDDEN", "PERMISSION_DENIED"}:
                raise HTTPException(
                    403,
                    "Wiz access denied. Manual scans require create:security_scans; "
                    "target lookup requires read:resources.",
                )
            raise HTTPException(502, "Wiz did not confirm the request. Check Wiz before retrying.")
        data = payload.get("data")
        if not isinstance(data, dict):
            raise HTTPException(502, "Wiz returned an invalid response.")
        return data

    def resources(self, account: str) -> list[ScanTarget]:
        targets: dict[str, ScanTarget] = {}
        after = None
        cursors: set[str] = set()
        while True:
            data = self.graphql(
                RESOURCES_QUERY,
                {"after": after, "filterBy": {
                    "subscriptionExternalId": [account], "type": ["VIRTUAL_MACHINE"],
                }},
            )
            connection = data.get("cloudResources")
            if not isinstance(connection, dict) or not isinstance(connection.get("nodes"), list):
                raise HTTPException(502, "Wiz returned invalid resource inventory.")
            for resource in connection["nodes"]:
                if not isinstance(resource, dict):
                    raise HTTPException(502, "Wiz returned an invalid resource.")
                entity = resource.get("graphEntity")
                if entity is None:
                    continue
                if not isinstance(entity, dict):
                    raise HTTPException(502, "Wiz returned an invalid resource entity.")
                properties = entity.get("properties")
                if not isinstance(properties, dict):
                    raise HTTPException(502, "Wiz returned invalid resource properties.")
                arn = properties.get("providerUniqueId")
                match = EC2_ARN.fullmatch(arn) if isinstance(arn, str) else None
                if not match or properties.get("status") != "Active":
                    continue
                if match[2] != account:
                    raise HTTPException(502, "Wiz returned a resource from an unexpected account.")
                if not isinstance(resource.get("id"), str) or not isinstance(resource.get("name"), str):
                    raise HTTPException(502, "Wiz returned an invalid resource identity.")
                targets[arn] = ScanTarget(
                    id=resource["id"], name=resource["name"], resource_id=match[3],
                    arn=arn, environment=account, region=match[1],
                )
            page = connection.get("pageInfo")
            if not isinstance(page, dict) or type(page.get("hasNextPage")) is not bool:
                raise HTTPException(502, "Wiz returned invalid resource pagination.")
            if not page["hasNextPage"]:
                break
            after = page.get("endCursor")
            if not isinstance(after, str) or not after or after in cursors:
                raise HTTPException(502, "Wiz returned an invalid or repeated resource cursor.")
            cursors.add(after)
        return sorted(targets.values(), key=lambda target: (target.name, target.resource_id, target.region))

    def start_scan(self, target: ScanTarget) -> None:
        data = self.graphql(START_SCAN, {"input": {"resourceID": target.arn}})
        result = data.get("initiateDiskScanVirtualMachine")
        if not isinstance(result, dict) or not isinstance(result.get("token"), str) or not result["token"]:
            raise HTTPException(502, "Wiz did not return a scan handle. Check Wiz before retrying.")
