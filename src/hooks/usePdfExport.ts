import { useCallback } from 'react';
import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { KEVMatch, Vulnerability } from '@/types/vulnerability';

const formatExposure = (vulnerability: Vulnerability) =>
  [vulnerability.service, vulnerability.port, vulnerability.protocol].filter(Boolean).join('/') || 'Host-level';

const truncate = (value: string, max = 120) =>
  value.length > max ? `${value.slice(0, max - 1)}...` : value;

const getSeverityPdfColors = (severity: string) => {
  switch (severity) {
    case 'Critical':
      return { fill: [220, 38, 38] as [number, number, number], text: [255, 255, 255] as [number, number, number] };
    case 'High':
      return { fill: [234, 88, 12] as [number, number, number], text: [255, 255, 255] as [number, number, number] };
    case 'Medium':
      return { fill: [217, 119, 6] as [number, number, number], text: [255, 255, 255] as [number, number, number] };
    case 'Low':
      return { fill: [37, 99, 235] as [number, number, number], text: [255, 255, 255] as [number, number, number] };
    default:
      return { fill: [100, 116, 139] as [number, number, number], text: [255, 255, 255] as [number, number, number] };
  }
};

export const usePdfExport = () => {
  const exportToPdf = useCallback((vulnerabilities: Vulnerability[], customerName?: string, kevMatches?: KEVMatch[]) => {
    const doc = new jsPDF({ orientation: 'portrait', unit: 'pt', format: 'a4' });
    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();
    const margin = 40;

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
    const uniqueIps = new Set(vulnerabilities.map((vulnerability) => vulnerability.ipAddress).filter(Boolean)).size;
    const uniqueCves = new Set(vulnerabilities.flatMap((vulnerability) => vulnerability.cves || [])).size;
    const withRemediation = vulnerabilities.filter((vulnerability) => vulnerability.solution).length;

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

    doc.setFillColor(6, 17, 31);
    doc.rect(0, 0, pageWidth, 120, 'F');
    doc.setTextColor(229, 238, 249);
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(24);
    doc.text(`Vulnerability Report${customerName ? ` - ${customerName}` : ''}`, margin, 50);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(10);
    doc.text(`Generated ${new Date().toLocaleString()}`, margin, 70);

    let y = 145;

    const metrics = [
      { label: 'Findings', value: String(vulnerabilities.length), fill: [241, 245, 249] as [number, number, number], text: [15, 23, 42] as [number, number, number] },
      { label: 'Critical', value: String(severityCounts.Critical), ...getSeverityPdfColors('Critical') },
      { label: 'High', value: String(severityCounts.High), ...getSeverityPdfColors('High') },
      { label: 'Medium', value: String(severityCounts.Medium), ...getSeverityPdfColors('Medium') },
      { label: 'Low', value: String(severityCounts.Low), ...getSeverityPdfColors('Low') },
      { label: 'Assets', value: String(uniqueAssets), fill: [241, 245, 249] as [number, number, number], text: [15, 23, 42] as [number, number, number] },
      { label: 'IPs', value: String(uniqueIps), fill: [241, 245, 249] as [number, number, number], text: [15, 23, 42] as [number, number, number] },
      { label: 'Unique CVEs', value: String(uniqueCves), fill: [241, 245, 249] as [number, number, number], text: [15, 23, 42] as [number, number, number] },
      { label: 'With Remediation', value: String(withRemediation), fill: [241, 245, 249] as [number, number, number], text: [15, 23, 42] as [number, number, number] },
    ];

    doc.setTextColor(15, 23, 42);
    metrics.forEach((metric, index) => {
      const x = margin + (index % 3) * 170;
      const row = Math.floor(index / 3);
      const top = y + row * 72;
      doc.setFillColor(...metric.fill);
      doc.roundedRect(x, top, 150, 56, 10, 10, 'F');
      doc.setTextColor(...metric.text);
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(18);
      doc.text(metric.value, x + 12, top + 24);
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(9);
      doc.text(metric.label.toUpperCase(), x + 12, top + 42);
    });

    y += 160;

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(14);
    doc.text('Severity Breakdown', margin, y);
    y += 12;

    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [['Severity', 'Count']],
      body: Object.entries(severityCounts),
      theme: 'grid',
      headStyles: { fillColor: [15, 23, 42] },
      styles: { fontSize: 10 },
      didParseCell: (data) => {
        if (data.section === 'body' && data.column.index === 0) {
          const colors = getSeverityPdfColors(String(data.cell.raw));
          data.cell.styles.fillColor = colors.fill;
          data.cell.styles.textColor = colors.text;
          data.cell.styles.fontStyle = 'bold';
        }
      },
    });

    y = (doc as jsPDF & { lastAutoTable?: { finalY: number } }).lastAutoTable?.finalY || y;
    y += 24;

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(14);
    doc.text('Top Exposed Services', margin, y);
    y += 12;

    autoTable(doc, {
      startY: y,
      margin: { left: margin, right: margin },
      head: [['Exposure', 'Count']],
      body: topServices.length > 0 ? topServices.map(([service, count]) => [service, String(count)]) : [['No service-level findings', '0']],
      theme: 'grid',
      headStyles: { fillColor: [15, 23, 42] },
      styles: { fontSize: 10 },
    });

    y = (doc as jsPDF & { lastAutoTable?: { finalY: number } }).lastAutoTable?.finalY || y;

    const addFindingsTable = (title: string, rows: Vulnerability[]) => {
      if (y > pageHeight - 180) {
        doc.addPage();
        y = margin;
      }

      y += 24;
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(14);
      doc.text(title, margin, y);
      y += 12;

      autoTable(doc, {
        startY: y,
        margin: { left: margin, right: margin },
        head: [['ID', 'Finding', 'Asset', 'Exposure', 'Severity', 'Score']],
        body: rows.length > 0
          ? rows.map((row) => [
              row.id,
              truncate(`${row.title}${row.cves?.length ? ` | ${row.cves.slice(0, 2).join(', ')}` : ''}`, 70),
              truncate(row.asset || row.ipAddress || 'Unknown', 28),
              truncate(formatExposure(row), 20),
              row.severity,
              row.score.toFixed(1),
            ])
          : [['-', 'No findings in this category', '-', '-', '-', '-']],
        theme: 'striped',
        headStyles: { fillColor: [15, 23, 42] },
        styles: { fontSize: 9, cellPadding: 6 },
        columnStyles: {
          0: { cellWidth: 70 },
          1: { cellWidth: 190 },
          2: { cellWidth: 110 },
          3: { cellWidth: 90 },
          4: { cellWidth: 60, halign: 'center' },
          5: { cellWidth: 45, halign: 'right' },
        },
        didParseCell: (data) => {
          if (data.section === 'body' && data.column.index === 4) {
            const colors = getSeverityPdfColors(String(data.cell.raw));
            data.cell.styles.fillColor = colors.fill;
            data.cell.styles.textColor = colors.text;
            data.cell.styles.fontStyle = 'bold';
          }
        },
      });

      y = (doc as jsPDF & { lastAutoTable?: { finalY: number } }).lastAutoTable?.finalY || y;
    };

    if (kevMatches && kevMatches.length > 0) {
      addFindingsTable(
        'Known Exploited Vulnerabilities',
        kevMatches.slice(0, 10).map((match) => ({
          ...match.vulnerability,
          title: `${match.kevEntry.cveID} - ${match.kevEntry.vulnerabilityName}`,
        }))
      );
    }

    addFindingsTable('Critical Findings', topBySeverity('Critical'));
    addFindingsTable('High Findings', topBySeverity('High'));
    addFindingsTable('Medium Findings', topBySeverity('Medium'));

    doc.save(`vulnerability-report-${new Date().toISOString().split('T')[0]}.pdf`);
  }, []);

  return { exportToPdf };
};
