# Manual Wiz scans

Both **EU_US_PROD** and **Wiz Security Overview** have a **Run manual scan**
button in the dashboard header. It opens `http://localhost:8085/scan` in a
new tab. If Grafana is accessed from another machine, update the dashboard
link URLs to the externally reachable webhook address and use HTTPS.

Enter `ANNOTATION_WEBHOOK_TOKEN`, load the environments, and select an AWS
account. Choose one EC2 instance or the entire environment, then confirm
**Start manual scan**. The token is not embedded in dashboard files, URLs,
or browser storage. Close the tab when finished.

The environment list comes from collected AWS account metadata. Resources
are loaded from live Wiz inventory, including instances without stored
findings. Only active EC2 instances are eligible; Auto Scaling
representatives and inactive resources are excluded. Environment scans
include all eligible instances in that account at submission time.

## Permissions and outcomes

The existing Wiz service account needs `read:resources` for target lookup
and `create:security_scans` for backend VM scans. Missing permissions produce
an explicit error. There is no collector-refresh or audit-only fallback.
No existing credentials are changed.

The service sends each target's full EC2 ARN to Wiz's
`initiateDiskScanVirtualMachine` mutation. Wiz acceptance is **not**
completion. Check Wiz for results. Scan handles and OAuth tokens are never
returned to the browser or written into annotations.

Submissions and outcomes are recorded in `wiz_annotations`. A batch stops
at its first error. Already accepted requests are listed separately from
rejected, unconfirmed, and not-attempted targets. A network failure can
leave acceptance uncertain: check Wiz before retrying to avoid duplicate
scans. If an audit update fails after submission, the API reports that
scans may already have started.

## API

All API routes require `X-API-Key: <ANNOTATION_WEBHOOK_TOKEN>`.

- `GET /api/v1/scan/environments`: known AWS account IDs and names.
- `GET /api/v1/scan/resources?environment=<account-id>`: active EC2 targets.
- `POST /api/v1/scan/run`: real scans, with the payload below.

```json
{
  "environment": "123456789012",
  "resource_id": "arn:aws:ec2:us-east-1:123456789012:instance/i-0123456789abcdef0",
  "scan_type": "full"
}
```

Omit `resource_id` to scan the entire account. The environment is required
and may be an exact account ID or unique subscription name. Resource IDs
may be a Wiz ID, full ARN, or unambiguous EC2 instance ID.

All accepted: HTTP `202`. Partial batch failure: HTTP `207` with per-target
outcomes. Nothing accepted: an explicit error such as HTTP `403`.

The original `POST /api/v1/scan` and
`scripts/Invoke-WizScan.ps1` remain **audit-only** for compatibility.
They do not start a security scan.
