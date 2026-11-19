<#
.SYNOPSIS
Posts a deployment or maintenance event to the Wiz annotation webhook.
.DESCRIPTION
Reads the API key from ANNOTATION_WEBHOOK_TOKEN unless -Token is supplied.
Use -EventTime with an explicit UTC offset to backdate an event; otherwise
the database supplies the current time.
The webhook writes to PostgreSQL; provisioned Grafana dashboards display the
event on their next refresh. Use HTTPS through a TLS reverse proxy for remote
callers, or restrict port 8085 to a trusted network.
.EXAMPLE
.\scripts\Send-GrafanaAnnotation.ps1 -Title "Release deployed" -Environment "us-prod"
.EXAMPLE
.\scripts\Send-GrafanaAnnotation.ps1 -Title "Maintenance" -Description "Database maintenance" -Environment "eu-prod" -Tags "maintenance,pillcam-devops"
.EXAMPLE
.\scripts\Send-GrafanaAnnotation.ps1 -Title "Node rotation" -Environment "PROD" -Tags "maintenance,node-rotation,prod" -EventTime "2026-11-15T00:00:00+02:00"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(1, 255)]
    [string]$Title,

    [string]$Description,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [ValidateLength(1, 150)]
    [string]$Environment,

    [ValidateLength(0, 100)]
    [string]$Tags = "deploy,pillcam-devops",

    [datetimeoffset]$EventTime,

    [ValidateScript({ $_.Scheme -in @("http", "https") })]
    [uri]$WebhookUrl = "http://localhost:8085/api/v1/annotations",

    [string]$Token = $env:ANNOTATION_WEBHOOK_TOKEN
)

if ([string]::IsNullOrWhiteSpace($Token)) {
    throw "Pass -Token or set the ANNOTATION_WEBHOOK_TOKEN environment variable."
}

$payload = @{
    title = $Title
    environment = $Environment
    tags = $Tags
}
if ($PSBoundParameters.ContainsKey("Description")) {
    $payload.description = $Description
}
if ($PSBoundParameters.ContainsKey("EventTime")) {
    $payload.event_time = $EventTime.ToString("o", [System.Globalization.CultureInfo]::InvariantCulture)
}

$body = [System.Text.Encoding]::UTF8.GetBytes(($payload | ConvertTo-Json -Compress))
Invoke-RestMethod -Uri $WebhookUrl -Method Post `
    -Headers @{ "X-API-Key" = $Token } `
    -ContentType "application/json; charset=utf-8" `
    -Body $body -TimeoutSec 30 -ErrorAction Stop
