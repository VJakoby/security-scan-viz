# Security Scan Visualization

React/Vite dashboard for importing vulnerability scanner output and turning it into a reportable view with asset, IP, service, CVE, severity, and remediation context intact.

## Current capabilities

- Auto-detects and normalizes Nessus CSV exports
- Auto-detects and normalizes Nessus `.nessus` / XML exports
- Auto-detects and normalizes Rapid7 Nexpose / InsightVM CSV exports
- Auto-detects and normalizes Nexpose XML exports
- Parses Nmap `.nmap` output into dashboard-ready findings
- Supports generic CSV and Excel uploads through manual column mapping
- Preserves richer finding context during import, including port, protocol, service, CVEs, description, solution, scanner, and source file
- Keeps per-host and per-service findings distinct instead of collapsing them into a single deduped issue
- Enriches findings against CISA KEV data when CVEs match
- Exports reports to standalone HTML and PDF
- Persists imported data, customer name, visualization settings, and import metadata in `localStorage` until cleared

## Dashboard views

- Summary cards for findings, severity, assets, IPs, CVEs, and remediation coverage
- Severity, score, asset, and IP visualizations
- Finding, asset, IP, frequency, service/port, and KEV tables
- Scanner/source breakdown and top remediation/service exposure summaries

## Supported inputs

Automatic import:

- `.csv` for Nessus and Nexpose/InsightVM exports
- `.nessus` and `.xml` for Nessus and Nexpose XML exports
- `.nmap` for Nmap output

Manual mapping:

- `.csv`
- `.xlsx`
- `.xls`

If a tabular file is not recognized as a scanner export, the app falls back to manual column mapping.

## Local development

```bash
npm ci
npm run dev
```

Available scripts:

```bash
npm run build
npm run build:dev
npm run lint
npm run preview
```

## Docker

Run with Docker Compose:

```bash
docker-compose up --build
```

Or build and run the image directly:

```bash
docker build -t vulnerability-dashboard .
docker run -p 8888:8888 vulnerability-dashboard
```

The containerized app is served at `http://localhost:8888`.

## Notes

- KEV data is fetched from CISA and cached locally for 24 hours; if it is unavailable, the dashboard continues without KEV matches.
- Demo data can be generated with `fake-nessus-results.py`.
- The project still contains some generated UI scaffolding from its original Lovable bootstrap.
