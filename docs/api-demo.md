# ThreatGuard API demonstration

Base URL: `http://localhost:5000/api`. All scan and dashboard routes require the anonymous browser capability header:

```http
X-Anonymous-Token: <43-character-base64url-browser-capability>
```

Open ThreatGuard in the browser and use its generated token from that browser's local storage for local API demonstrations. Treat it as a secret: anyone with it can access or delete that browser's reports. The API stores only its SHA-256 hash. Do not paste a real token into source control or screenshots.

Successful scan responses contain the saved MongoDB document under `scan`, including `_id`, `createdAt`, `riskScore`, `threatLevel`, `indicators`, `recommendations`, `limitations`, and (where applicable) `checks`. A successful scan is saved before HTTP 201 is returned.

## Health

`GET /health` — no capability required.

```powershell
Invoke-RestMethod http://localhost:5000/api/health
```

Response shape:

```json
{"status":"ok","database":"connected"}
```

The database field may be `disconnected` if Mongoose is not ready. The endpoint never returns credentials.

## Website scan

`POST /scans/website` — capability required; JSON body.

```powershell
$headers = @{ 'X-Anonymous-Token' = '<your local browser capability>' }
Invoke-RestMethod http://localhost:5000/api/scans/website -Method Post -Headers $headers -ContentType 'application/json' -Body '{"url":"https://www.wikipedia.org/"}'
```

Checks are real per-request results: DNS A/AAAA/MX/NS, certificate verification and metadata when HTTPS connects, a bounded redirect chain, and the rule-based analysis mode. A check may be unavailable when the network prevents it from running; no threat-intelligence, antivirus, or malware scan is performed.

Example error: malformed URL returns HTTP 400 with `{"error":"Enter a valid HTTP or HTTPS website URL with a fully qualified domain name."}`. Local, private, reserved, metadata, and nonstandard outbound targets are rejected or blocked from fetching.

## Email scan

`POST /scans/email` — capability required; JSON body.

Required fields: `sender`, `subject`, and `body`. Optional fields: `displayName`, `urls`, and `headers`.

```powershell
$payload = @{ sender='alerts@example.com'; displayName='Support'; subject='Account notice'; body='Please review this account notice in the usual portal.' } | ConvertTo-Json
Invoke-RestMethod http://localhost:5000/api/scans/email -Method Post -Headers $headers -ContentType 'application/json' -Body $payload
```

Invalid sender, empty subject, or body with fewer than ten non-whitespace characters returns HTTP 400. Optional header evidence is unverified user-supplied text; it does not establish SPF, DKIM, DMARC, or sender authenticity.

## PDF scan

`POST /scans/pdf` — capability required; multipart field name `file`; maximum size is `UPLOAD_MAX_MB` (10 MB by default).

```powershell
$form = @{ file = Get-Item '.\sample.pdf' }
Invoke-RestMethod http://localhost:5000/api/scans/pdf -Method Post -Headers $headers -Form $form
```

The API validates extension, MIME type, signature, and readable text. It returns HTTP 400 for no file, invalid/corrupt/encrypted input, or a document with no meaningful machine-readable text. OCR is not enabled.

## Scan history, report, and deletion

- `GET /scans` — own scans, newest first; optional `type`, `level`, `q`, `sort`, `page`, and `limit` query parameters.
- `GET /scans/:id` — retrieve a report owned by this capability.
- `DELETE /scans/:id` — delete one owned scan.
- `DELETE /scans` — delete all scans belonging to this capability.

Every request requires `X-Anonymous-Token`. Missing or malformed capability returns HTTP 401. A valid capability that does not own a report receives HTTP 404.

## Dashboard analytics

- `GET /dashboard/stats` — actual completed owned scans, grouped by `safe`, `medium`, `high` and analyzer type; includes six newest reports.
- `GET /dashboard/activity` — completed owned scans from the last 30 days, optionally filtered with `type=website|email|pdf`.

Both routes require `X-Anonymous-Token`. Unknown or missing threat levels are not silently counted as Safe.

## Authentication endpoints

There are no registration, login, JWT, or user-account endpoints in the current application. Scan ownership is provided by the anonymous browser capability instead.

## Common errors

- `400` — invalid request, invalid URL/email/PDF, or size limit.
- `401` — missing or malformed anonymous capability.
- `404` — report is absent or belongs to another capability.
- `429` — API rate limit reached.
- `500` — safe generic error response; server logs omit submitted content and credentials.
