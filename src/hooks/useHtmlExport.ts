import { useCallback } from 'react';
import { KEVMatch, Vulnerability } from '@/types/vulnerability';

const escapeHtml = (value: string): string =>
  value
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');

const getSeverityColor = (severity: string) => {
  switch (severity) {
    case 'Critical': return '#dc2626';
    case 'High': return '#ea580c';
    case 'Medium': return '#d97706';
    case 'Low': return '#16a34a';
    default: return '#64748b';
  }
};

const formatExposure = (vulnerability: Vulnerability) =>
  [vulnerability.service, vulnerability.port, vulnerability.protocol].filter(Boolean).join('/') || 'Host-level';

const renderRows = (vulnerabilities: Vulnerability[]) => {
  if (vulnerabilities.length === 0) {
    return '<tr><td colspan="7" style="text-align:center;color:#94a3b8;">No findings in this category</td></tr>';
  }

  return vulnerabilities.map((vulnerability) => `
    <tr>
      <td style="font-family:monospace;">${escapeHtml(vulnerability.id)}</td>
      <td>
        <div style="font-weight:600;">${escapeHtml(vulnerability.title)}</div>
        <div style="font-size:12px;color:#94a3b8;">${escapeHtml((vulnerability.cves || []).slice(0, 3).join(', ') || vulnerability.scanner || 'Generic')}</div>
      </td>
      <td>${escapeHtml(vulnerability.asset || 'Unknown')}</td>
      <td style="font-family:monospace;">${escapeHtml(vulnerability.ipAddress || '')}</td>
      <td style="font-size:12px;">${escapeHtml(formatExposure(vulnerability))}</td>
      <td><span style="display:inline-block;padding:4px 8px;border-radius:999px;background:${getSeverityColor(vulnerability.severity)};color:white;font-size:12px;">${escapeHtml(vulnerability.severity)}</span></td>
      <td style="font-family:monospace;">${vulnerability.score.toFixed(1)}</td>
    </tr>
  `).join('');
};

const renderKevRows = (matches: KEVMatch[]) => {
  if (matches.length === 0) {
    return '<tr><td colspan="6" style="text-align:center;color:#94a3b8;">No KEV matches found</td></tr>';
  }

  return matches.slice(0, 10).map((match) => `
    <tr>
      <td style="font-family:monospace;font-weight:600;">${escapeHtml(match.kevEntry.cveID)}</td>
      <td>${escapeHtml(match.kevEntry.vulnerabilityName)}</td>
      <td>${escapeHtml(match.vulnerability.asset)}</td>
      <td>${escapeHtml(formatExposure(match.vulnerability))}</td>
      <td style="font-family:monospace;">${match.vulnerability.score.toFixed(1)}</td>
      <td>${escapeHtml(match.kevEntry.knownRansomwareCampaignUse || 'Unknown')}</td>
    </tr>
  `).join('');
};

export const useHtmlExport = () => {
  const exportToHtml = useCallback((vulnerabilities: Vulnerability[], customerName?: string, kevMatches?: KEVMatch[]) => {
    const severityCounts = vulnerabilities.reduce((acc, vulnerability) => {
      acc[vulnerability.severity] += 1;
      return acc;
    }, {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      Unknown: 0,
    });

    const uniqueAssets = new Set(vulnerabilities.map((vulnerability) => vulnerability.asset).filter(Boolean)).size;
    const uniqueCves = new Set(vulnerabilities.flatMap((vulnerability) => vulnerability.cves || [])).size;
    const remediatedWithGuidance = vulnerabilities.filter((vulnerability) => vulnerability.solution).length;

    const topBySeverity = (severity: Vulnerability['severity']) =>
      vulnerabilities
        .filter((vulnerability) => vulnerability.severity === severity)
        .sort((left, right) => right.score - left.score)
        .slice(0, 10);

    const topServices = Object.entries(
      vulnerabilities.reduce((acc, vulnerability) => {
        const key = formatExposure(vulnerability);
        acc[key] = (acc[key] || 0) + 1;
        return acc;
      }, {} as Record<string, number>)
    )
      .sort((left, right) => right[1] - left[1])
      .slice(0, 10);

    const htmlContent = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vulnerability Report - ${new Date().toLocaleDateString()}</title>
  <style>
    body { margin: 0; font-family: Inter, Arial, sans-serif; background: #08111f; color: #e5eef9; }
    .page { max-width: 1280px; margin: 0 auto; padding: 32px 20px 48px; }
    .hero { padding: 32px; border-radius: 24px; background: linear-gradient(135deg, #102541, #0d5f8f); box-shadow: 0 20px 60px rgba(0,0,0,.35); }
    .hero h1 { margin: 0 0 8px; font-size: 40px; }
    .hero p { margin: 0; color: rgba(229,238,249,.8); }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-top: 24px; }
    .card { background: rgba(8,17,31,.7); border: 1px solid rgba(148,163,184,.18); border-radius: 18px; padding: 18px; }
    .metric { font-size: 30px; font-weight: 700; margin-bottom: 6px; }
    .label { color: #9fb2c8; font-size: 13px; text-transform: uppercase; letter-spacing: .06em; }
    h2 { margin-top: 36px; margin-bottom: 14px; font-size: 22px; }
    table { width: 100%; border-collapse: collapse; background: rgba(15,23,42,.72); border-radius: 18px; overflow: hidden; }
    th, td { padding: 14px 12px; border-bottom: 1px solid rgba(148,163,184,.14); text-align: left; vertical-align: top; }
    th { color: #7dd3fc; font-size: 13px; text-transform: uppercase; letter-spacing: .05em; background: rgba(8,17,31,.75); }
    .section { margin-top: 28px; }
    .pill { display: inline-block; padding: 4px 10px; border-radius: 999px; background: rgba(125,211,252,.12); color: #7dd3fc; font-size: 12px; }
    .service-grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 12px; }
    .service-card { padding: 16px; border-radius: 16px; background: rgba(15,23,42,.72); border: 1px solid rgba(148,163,184,.14); }
    .footer { margin-top: 36px; color: #9fb2c8; font-size: 13px; }
    @media print {
      body { background: white; color: black; }
      .hero, .card, table, .service-card { background: white; color: black; box-shadow: none; border-color: #cbd5e1; }
      th { color: #0f172a; background: #e2e8f0; }
    }
  </style>
</head>
<body>
  <div class="page">
    <section class="hero">
      <h1>Vulnerability Report${customerName ? ` - ${escapeHtml(customerName)}` : ''}</h1>
      <p>Generated ${escapeHtml(new Date().toLocaleString())}</p>
      <div class="grid">
        <div class="card"><div class="metric">${vulnerabilities.length}</div><div class="label">Findings</div></div>
        <div class="card"><div class="metric">${uniqueAssets}</div><div class="label">Assets</div></div>
        <div class="card"><div class="metric">${severityCounts.Critical + severityCounts.High}</div><div class="label">Critical + High</div></div>
        <div class="card"><div class="metric">${uniqueCves}</div><div class="label">Unique CVEs</div></div>
        <div class="card"><div class="metric">${remediatedWithGuidance}</div><div class="label">With Remediation</div></div>
      </div>
    </section>

    <section class="section">
      <h2>Severity Breakdown</h2>
      <div class="grid">
        ${Object.entries(severityCounts).map(([severity, count]) => `
          <div class="card">
            <div class="pill" style="background:${getSeverityColor(severity)}22;color:${getSeverityColor(severity)}">${escapeHtml(severity)}</div>
            <div class="metric">${count}</div>
          </div>
        `).join('')}
      </div>
    </section>

    <section class="section">
      <h2>Top Exposed Services</h2>
      <div class="service-grid">
        ${topServices.map(([service, count]) => `
          <div class="service-card">
            <div style="font-family:monospace;font-size:14px;">${escapeHtml(service)}</div>
            <div class="metric">${count}</div>
          </div>
        `).join('') || '<div class="service-card">No service-level findings</div>'}
      </div>
    </section>

    ${kevMatches && kevMatches.length > 0 ? `
      <section class="section">
        <h2>Known Exploited Vulnerabilities</h2>
        <table>
          <thead>
            <tr>
              <th>CVE</th>
              <th>Name</th>
              <th>Asset</th>
              <th>Exposure</th>
              <th>Score</th>
              <th>Ransomware</th>
            </tr>
          </thead>
          <tbody>${renderKevRows(kevMatches)}</tbody>
        </table>
      </section>
    ` : ''}

    <section class="section">
      <h2>Critical Findings</h2>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Finding</th>
            <th>Asset</th>
            <th>IP</th>
            <th>Exposure</th>
            <th>Severity</th>
            <th>Score</th>
          </tr>
        </thead>
        <tbody>${renderRows(topBySeverity('Critical'))}</tbody>
      </table>
    </section>

    <section class="section">
      <h2>High Findings</h2>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Finding</th>
            <th>Asset</th>
            <th>IP</th>
            <th>Exposure</th>
            <th>Severity</th>
            <th>Score</th>
          </tr>
        </thead>
        <tbody>${renderRows(topBySeverity('High'))}</tbody>
      </table>
    </section>

    <section class="section">
      <h2>Medium Findings</h2>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Finding</th>
            <th>Asset</th>
            <th>IP</th>
            <th>Exposure</th>
            <th>Severity</th>
            <th>Score</th>
          </tr>
        </thead>
        <tbody>${renderRows(topBySeverity('Medium'))}</tbody>
      </table>
    </section>

    <div class="footer">Report generated by Vulnerability Dashboard.</div>
  </div>
</body>
</html>`;

    const blob = new Blob([htmlContent], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `vulnerability-report-${new Date().toISOString().split('T')[0]}.html`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }, []);

  return { exportToHtml };
};
