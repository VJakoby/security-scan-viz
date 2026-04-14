# Security Scan Visualization

React/Vite dashboard for importing vulnerability scanner output and turning it into a reportable view with asset, service, CVE, severity, and remediation context.

## What it handles

- Nessus CSV exports
- Nessus `.nessus` XML exports
- Rapid7 Nexpose / InsightVM CSV exports
- Nexpose XML exports
- Nmap `.nmap` output
- Generic CSV / Excel files through manual column mapping

## Improvements in this version

- Added scanner-aware auto-detection for Nessus and Nexpose imports
- Preserved richer fields during import: port, protocol, service, CVEs, description, solution, scanner source
- Removed the old dedupe behavior that incorrectly collapsed the same vulnerability across multiple hosts
- Expanded the dashboard with source breakdown, remediation coverage, exposed services, richer finding tables, and better report export
- Upgraded the HTML export to include more operational data instead of only severity slices

## Local usage

```bash
npm ci
npm run dev
```

Build for production:

```bash
npm run build
```

Lint:

```bash
npm run lint
```

Access the dashboard at `http://localhost:8888` when running through the provided Docker setup.

## Notes

- Generic CSV / Excel uploads can still be mapped manually when the file is not auto-recognized.
- Demo data can be generated with `fake-nessus-results.py`.
- The project originated from Lovable and still contains some generated UI scaffolding.
