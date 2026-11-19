<#
.SYNOPSIS
Records an on-demand Wiz scan request for manual review.
.DESCRIPTION
Posts to the authenticated scan endpoint using ANNOTATION_WEBHOOK_TOKEN unless
-Token is supplied. The endpoint records an audit event in wiz_annotations;
it does not queue or execute a Wiz scan or a collector synchronization.
Environment and ResourceId are optional. Omitted targets remain unspecified.
Use HTTPS through a TLS reverse proxy for remote callers, or restrict port 8085
to a trusted network.
.EXAMPLE
.\scripts\Invoke-WizScan.ps1 -Environment "PROD" -ResourceId "i-0123456789abcdef0"
.EXAMPLE
.\scripts\Invoke-WizScan.ps1 -Environment "eu-prod" -ScanType "full"
#>
[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [ValidateLength(1, 150)]
    [string]$Environment,

    [ValidateNotNullOrEmpty()]
    [string]$ResourceId,

    [ValidateNotNullOrEmpty()]
    [string]$ScanType = "full",

    [ValidateScript({ $_.Scheme -in @("http", "https") })]
    [uri]$WebhookUrl = "http://localhost:8085/api/v1/scan",

    [string]$Token = $env:ANNOTATION_WEBHOOK_TOKEN
)

if ([string]::IsNullOrWhiteSpace($Token)) {
    throw "Pass -Token or set the ANNOTATION_WEBHOOK_TOKEN environment variable."
}

$payload = @{ scan_type = $ScanType }
if ($PSBoundParameters.ContainsKey("Environment")) {
    $payload.environment = $Environment
}
if ($PSBoundParameters.ContainsKey("ResourceId")) {
    $payload.resource_id = $ResourceId
}

$body = [System.Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress))
Invoke-RestMethod -Uri $WebhookUrl -Method Post `
    -Headers @{ "X-API-Key" = $Token } `
    -ContentType "application/json; charset=utf-8" `
    -Body $body -TimeoutSec 30 -ErrorAction Stop
