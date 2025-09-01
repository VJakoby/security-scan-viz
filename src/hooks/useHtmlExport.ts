import { useCallback } from 'react';
import { Vulnerability, ProtocolCount, KEVMatch } from '@/types/vulnerability';

export const useHtmlExport = () => {
  const exportToHtml = useCallback((vulnerabilities: Vulnerability[], customerName?: string, kevMatches?: KEVMatch[]) => {
    const severityCounts = vulnerabilities.reduce((acc, vuln) => {
      acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
      return acc;
    }, {
      Critical: 0,
      High: 0,
      Medium: 0,
      Low: 0,
      Unknown: 0
    });

    const criticalVulns = vulnerabilities
      .filter(v => v.severity === 'Critical')
      .sort((a, b) => b.score - a.score)
      .slice(0, 10);

    const highVulns = vulnerabilities
      .filter(v => v.severity === 'High')
      .sort((a, b) => b.score - a.score)
      .slice(0, 10);

    const mediumVulns = vulnerabilities
      .filter(v => v.severity === 'Medium')
      .sort((a, b) => b.score - a.score)
      .slice(0, 10);


    const generateTableRows = (vulns: Vulnerability[]) => {
      if (vulns.length === 0) {
        return '<tr><td colspan="5" style="text-align: center; font-style: italic; color: #666;">No vulnerabilities found</td></tr>';
      }
      return vulns.map(v => `
        <tr>
          <td style="font-family: monospace; font-size: 0.9em;">${v.id}</td>
          <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;">${v.title}</td>
          <td>${v.asset}</td>
          <td style="font-family: monospace; font-size: 0.9em;">${v.ipAddress}</td>
          <td><span style="padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; color: white; background-color: ${getSeverityColor(v.severity)};">${v.severity}</span></td>
          <td style="font-family: monospace;">${v.score.toFixed(1)}</td>
        </tr>
      `).join('');
    };

    const generateKEVTableRows = (matches: KEVMatch[]) => {
      if (matches.length === 0) {
        return '<tr><td colspan="7" style="text-align: center; font-style: italic; color: #666;">No Known Exploitable Vulnerabilities found</td></tr>';
      }
      return matches.slice(0, 10).map(match => `
        <tr style="background: rgba(220, 38, 38, 0.1); border-left: 4px solid #dc2626;">
          <td style="font-family: monospace; font-size: 0.9em; font-weight: bold;">${match.kevEntry.cveID}</td>
          <td style="max-width: 250px; overflow: hidden; text-overflow: ellipsis;">${match.kevEntry.vulnerabilityName}</td>
          <td>${match.kevEntry.vendorProject}<br><small style="color: #94a3b8;">${match.kevEntry.product}</small></td>
          <td>${match.vulnerability.asset}</td>
          <td style="font-family: monospace;">${match.vulnerability.score.toFixed(1)}</td>
          <td><span style="padding: 4px 8px; border-radius: 4px; font-size: 0.8em; font-weight: bold; color: white; background-color: ${getRansomwareColor(match.kevEntry.knownRansomwareCampaignUse)};">${match.kevEntry.knownRansomwareCampaignUse}</span></td>
          <td style="font-size: 0.9em;">${formatDate(match.kevEntry.dueDate)}</td>
        </tr>
      `).join('');
    };

    const formatDate = (dateString: string) => {
      try {
        return new Date(dateString).toLocaleDateString();
      } catch {
        return dateString;
      }
    };

    const getRansomwareColor = (status: string) => {
      switch (status?.toLowerCase()) {
        case 'known': return '#dc2626';
        case 'unknown': return '#6b7280';
        default: return '#6b7280';
      }
    };

    const getSeverityColor = (severity: string) => {
      switch (severity) {
        case 'Critical': return '#dc2626';
        case 'High': return '#ea580c';
        case 'Medium': return '#d97706';
        case 'Low': return '#16a34a';
        default: return '#6b7280';
      }
    };

    const htmlContent = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Vulnerability Dashboard Report - ${new Date().toLocaleDateString()}</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      margin: 0;
      padding: 20px;
      background: linear-gradient(135deg, #0f1419 0%, #1a2332 100%);
      color: #e2e8f0;
      min-height: 100vh;
    }
    .container {
      max-width: 1200px;
      margin: 0 auto;
      background: rgba(15, 20, 25, 0.8);
      border-radius: 12px;
      padding: 30px;
      box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
    }
    h1 {
      text-align: center;
      color: #00d4ff;
      margin-bottom: 10px;
      font-size: 2.5em;
      font-weight: 700;
    }
    .subtitle {
      text-align: center;
      color: #94a3b8;
      margin-bottom: 30px;
      font-size: 1.1em;
    }
    .summary {
      background: rgba(30, 41, 59, 0.5);
      padding: 20px;
      border-radius: 8px;
      margin-bottom: 30px;
      border: 1px solid rgba(0, 212, 255, 0.2);
    }
    .summary h2 {
      color: #00d4ff;
      margin-top: 0;
      margin-bottom: 15px;
    }
    .stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 15px;
    }
    .stat-item {
      text-align: center;
      padding: 15px;
      background: rgba(15, 20, 25, 0.6);
      border-radius: 8px;
      border: 1px solid rgba(148, 163, 184, 0.2);
    }
    .stat-number {
      font-size: 2em;
      font-weight: bold;
      color: #00d4ff;
    }
    .stat-label {
      font-size: 0.9em;
      color: #94a3b8;
      margin-top: 5px;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 20px 0;
      background: rgba(30, 41, 59, 0.3);
      border-radius: 8px;
      overflow: hidden;
    }
    th {
      background: rgba(0, 212, 255, 0.1);
      color: #00d4ff;
      padding: 15px 12px;
      text-align: left;
      font-weight: 600;
      border-bottom: 2px solid rgba(0, 212, 255, 0.3);
    }
    td {
      padding: 12px;
      border-bottom: 1px solid rgba(148, 163, 184, 0.1);
    }
    tr:hover {
      background: rgba(0, 212, 255, 0.05);
    }
    h3 {
      color: #00d4ff;
      margin-top: 40px;
      margin-bottom: 15px;
      font-size: 1.5em;
    }
    .footer {
      margin-top: 40px;
      padding-top: 20px;
      border-top: 1px solid rgba(148, 163, 184, 0.2);
      text-align: center;
      color: #94a3b8;
      font-size: 0.9em;
    }
    @media print {
      body { background: white; color: black; }
      .container { background: white; box-shadow: none; }
      h1, h2, h3, th { color: #1e40af; }
      .stat-number { color: #1e40af; }
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🛡️ Vulnerability Dashboard Report${customerName ? ` - ${customerName}` : ''}</h1>
    <div class="subtitle">Generated on ${new Date().toLocaleString()}</div>
    
     <div class="summary">
      <h2>📊 Executive Summary</h2>
      <div class="stats">
        <div class="stat-item">
          <div class="stat-number">${vulnerabilities.length}</div>
          <div class="stat-label">Total Vulnerabilities</div>
        </div>
        <div class="stat-item" style="border: 2px solid #dc2626; background: rgba(220, 38, 38, 0.1);">
          <div class="stat-number" style="color: #dc2626;">${severityCounts.Critical}</div>
          <div class="stat-label">Critical</div>
        </div>
        <div class="stat-item" style="border: 2px solid #ea580c; background: rgba(234, 88, 12, 0.1);">
          <div class="stat-number" style="color: #ea580c;">${severityCounts.High}</div>
          <div class="stat-label">High</div>
        </div>
        <div class="stat-item" style="border: 2px solid #d97706; background: rgba(217, 119, 6, 0.1);">
          <div class="stat-number" style="color: #d97706;">${severityCounts.Medium}</div>
          <div class="stat-label">Medium</div>
        </div>
        <div class="stat-item" style="border: 2px solid #2563eb; background: rgba(37, 99, 235, 0.1);">
          <div class="stat-number" style="color: #2563eb;">${severityCounts.Low}</div>
          <div class="stat-label">Low</div>
        </div>
       </div>
     </div>

     ${kevMatches && kevMatches.length > 0 ? `
     <div class="summary" style="border: 2px solid #dc2626; background: rgba(220, 38, 38, 0.1);">
       <h2>⚠️ Known Exploitable Vulnerabilities (KEV)</h2>
       <p style="color: #fca5a5; margin-bottom: 15px;">
         ${kevMatches.length} vulnerabilities found in CISA's Known Exploited Vulnerabilities catalog.
         These require immediate attention as they are actively exploited in the wild.
       </p>
     </div>

     <h3>🚨 Top 10 Known Exploitable Vulnerabilities (KEV)</h3>
     <table>
       <thead>
         <tr>
           <th>CVE ID</th>
           <th>Vulnerability Name</th>
           <th>Vendor/Product</th>
           <th>Asset</th>
           <th>Score</th>
           <th>Ransomware Use</th>
           <th>Due Date</th>
         </tr>
       </thead>
       <tbody>
         ${generateKEVTableRows(kevMatches)}
       </tbody>
     </table>
     ` : ''}

     <h3>🔴 Critical Vulnerabilities (Top 10)</h3>
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Title</th>
          <th>Asset</th>
          <th>IP Address</th>
          <th>Severity</th>
          <th>Score</th>
        </tr>
      </thead>
      <tbody>
        ${generateTableRows(criticalVulns)}
      </tbody>
    </table>

    <h3>🟠 High Vulnerabilities (Top 10)</h3>
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Title</th>
          <th>Asset</th>
          <th>IP Address</th>
          <th>Severity</th>
          <th>Score</th>
        </tr>
      </thead>
      <tbody>
        ${generateTableRows(highVulns)}
      </tbody>
    </table>

    <h3>🟡 Medium Vulnerabilities (Top 10)</h3>
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Title</th>
          <th>Asset</th>
          <th>IP Address</th>
          <th>Severity</th>
          <th>Score</th>
        </tr>
      </thead>
      <tbody>
        ${generateTableRows(mediumVulns)}
      </tbody>
    </table>

     <div class="footer">
       <p>Report generated by Vulnerability Dashboard</p>
       <p>Contains ${vulnerabilities.length} total vulnerabilities across ${new Set(vulnerabilities.map(v => v.asset)).size} unique assets</p>
       ${kevMatches && kevMatches.length > 0 ? `<p style="color: #fca5a5; font-weight: bold;">⚠️ ${kevMatches.length} Known Exploitable Vulnerabilities requiring immediate attention</p>` : ''}
     </div>
  </div>
</body>
</html>
    `;

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