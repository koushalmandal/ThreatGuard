# ThreatGuard — Multi-Source Threat Analyzer

ThreatGuard is an existing React/Vite and Express application for explainable heuristic assessment of website URLs, email text, and PDF documents. Scan reports are stored in MongoDB and scoped to a cryptographically random anonymous browser capability. No login, registration, billing, or payment system is present in the active application.

## Requirements and setup

- Node.js 20 or later and npm
- MongoDB Atlas access for the configured cluster

From the project root in PowerShell:

```powershell
npm install
npm --prefix server install
Copy-Item server/.env.example server/.env
```

Set `MONGODB_URI` in `server/.env` using the current Atlas Drivers URI. Keep the password URL-encoded. Never put the URI or API keys in the frontend or `.env.example`. Configure Atlas Network Access to allow the development machine. The optional `MONGODB_DNS_SERVERS` can select a DNS resolver when the Windows resolver cannot resolve SRV records.

Optional variables:

- `UPLOAD_MAX_MB`: PDF size limit, default 10 MB.
- `CLIENT_ORIGIN`: comma-separated explicit frontend origins.

## Run and build

```powershell
npm run dev
npm test
npm run build
```

The root command starts Vite on `http://localhost:5173` and Express on port 5000. If Atlas does not connect, the root runner stops the frontend rather than leaving a misleading API-less session. Use `npm run dev:frontend` and `npm run dev:server` only for separate debugging; do not start multiple API instances on port 5000.

## Architecture

- `src/` — React routes, analyzer forms, report/history/dashboard UI, API client, anonymous capability, validation, and styling.
- `server/src/index.js` — dotenv loading, DNS resolver configuration, middleware, health route, and startup.
- `server/src/routes/api.js` — protected scan, history, report, dashboard, and activity APIs.
- `server/src/models/Scan.js` — MongoDB scan persistence and report schema.
- `server/src/services/scoring.js` — shared explainable scoring and classification.
- `server/src/services/website.js` and `websiteNetwork.js` — deterministic URL heuristics, DNS, pinned public-IP requests, TLS, and redirects. No external threat-intelligence service is used.
- `server/src/services/email.js` — in-memory email heuristic checks.
- `server/src/services/pdf.js` — PDF.js text extraction and supported plain-text structural markers.

## Privacy and protection

The browser creates a random capability and stores it in localStorage. It sends `X-Anonymous-Token` to the API; the API hashes it and stores only the hash as scan ownership. History, reports, deletion, and analytics are scoped to that hash. Clearing browser storage loses access to the existing reports. The Settings page can delete scans for the current capability.

Email body text, optional email header text, and uploaded PDF bytes are analyzed in memory and are not stored. Only summaries, findings, check statuses, recommendations, and report metadata persist. PDFs are held in memory by Multer and are not executed. Do not use a shared browser for sensitive material.

## Risk model and limits

The shared thresholds are 0–39 Safe/Low, 40–69 Medium Risk, and 70–100 High Risk/Unsafe. Scores are capped at 100. Each finding includes a category, severity, deterministic weight, explanation, evidence, and recommendation. A safe/low heuristic score is not a guarantee of safety or proof of malware.

Website DNS queries inspect A, AAAA, MX, and NS data. Remote website inspection uses only HTTP/HTTPS on ports 80/443, validates DNS destinations against private/reserved ranges, pins the resolved public address for each request, caps redirects and response bytes, rechecks every redirect, and relies on Node's normal TLS certificate/hostname verification. No site scripts or downloaded page content are executed. Network failures are shown as unavailable and are not treated as clean checks. If safe DNS pinning cannot be established, the remote request is stopped.

Website analysis uses deterministic URL structure rules plus the existing restricted DNS, TLS, and redirect checks. HTTP alone has a small five-point weight and cannot classify a URL as a threat. Private/reserved destinations are blocked before remote inspection. No threat-intelligence, antivirus, malware-signature, or machine-learning check is performed.

Email analysis does not verify sender identity. Optional header analysis displays only authentication claims parsed from the supplied text; supplied headers are untrusted and SPF, DKIM, and DMARC are not independently verified. PDF.js reads machine-readable text only. OCR is not enabled; compressed or obfuscated PDF structures may not be visible to the supported marker checks. This is not antivirus or a complete PDF malware scanner.

## API demonstration

The endpoint examples, headers, request bodies, response shapes, and error examples are documented in [docs/api-demo.md](docs/api-demo.md). There are no registration or login endpoints in this anonymous product.

## Tests and live checks

`npm test` runs deterministic local analyzer and URL destination screening tests. `npm run test:integration` requires the API and Atlas to be reachable; it creates and removes scans under a temporary random browser capability. It must not be run against production data.
