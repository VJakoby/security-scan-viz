import { useCallback } from 'react';
import { Vulnerability, ColumnMapping } from '@/types/vulnerability';

export const useStandaloneExport = () => {
  const exportStandaloneHtml = useCallback(() => {
    const standaloneHtml = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerability Dashboard - Standalone</title>
    <script src="https://unpkg.com/react@18.3.1/umd/react.production.min.js"></script>
    <script src="https://unpkg.com/react-dom@18.3.1/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/papaparse@5.4.1/papaparse.min.js"></script>
    <script src="https://unpkg.com/recharts@2.8.0/umd/Recharts.js"></script>
    <script src="https://unpkg.com/lucide-react@0.400.0/dist/umd/lucide-react.js"></script>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        /* Tailwind CSS Reset and Base Styles */
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        :root {
            --background: 220 39% 11%;
            --foreground: 0 0% 98%;
            --card: 220 26% 14%;
            --card-foreground: 0 0% 98%;
            --primary: 197 71% 73%;
            --primary-foreground: 220 39% 11%;
            --secondary: 220 26% 18%;
            --secondary-foreground: 0 0% 98%;
            --border: 220 26% 18%;
            --input: 220 26% 18%;
            --ring: 197 71% 73%;
            --radius: 0.75rem;
            --critical: 0 84% 60%;
            --high: 25 95% 53%;
            --medium: 45 93% 47%;
            --low: 142 71% 45%;
            --info: 217 91% 60%;
        }
        
        body {
            background-color: hsl(var(--background));
            color: hsl(var(--foreground));
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.5;
        }
        
        .card {
            background-color: hsl(var(--card));
            border: 1px solid hsl(var(--border));
            border-radius: var(--radius);
            padding: 1.5rem;
            margin: 1rem 0;
        }
        
        .card-header {
            margin-bottom: 1rem;
        }
        
        .card-title {
            font-size: 1.25rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }
        
        .card-description {
            color: hsl(var(--foreground) / 0.7);
            font-size: 0.875rem;
        }
        
        .button {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            padding: 0.5rem 1rem;
            border-radius: var(--radius);
            font-size: 0.875rem;
            font-weight: 500;
            cursor: pointer;
            border: none;
            transition: all 0.2s;
        }
        
        .button-primary {
            background-color: hsl(var(--primary));
            color: hsl(var(--primary-foreground));
        }
        
        .button-primary:hover {
            opacity: 0.9;
        }
        
        .button-secondary {
            background-color: hsl(var(--secondary));
            color: hsl(var(--secondary-foreground));
        }
        
        .input {
            background-color: hsl(var(--input));
            border: 1px solid hsl(var(--border));
            border-radius: var(--radius);
            padding: 0.5rem 0.75rem;
            color: hsl(var(--foreground));
            width: 100%;
        }
        
        .table {
            width: 100%;
            border-collapse: collapse;
            border-spacing: 0;
        }
        
        .table th,
        .table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid hsl(var(--border));
        }
        
        .table th {
            font-weight: 600;
            background-color: hsl(var(--secondary) / 0.5);
        }
        
        .badge {
            display: inline-flex;
            align-items: center;
            padding: 0.25rem 0.5rem;
            border-radius: calc(var(--radius) - 2px);
            font-size: 0.75rem;
            font-weight: 500;
        }
        
        .badge-critical { background-color: hsl(var(--critical)); color: white; }
        .badge-high { background-color: hsl(var(--high)); color: white; }
        .badge-medium { background-color: hsl(var(--medium)); color: white; }
        .badge-low { background-color: hsl(var(--low)); color: white; }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }
        
        .grid {
            display: grid;
            gap: 1rem;
        }
        
        .grid-cols-2 { grid-template-columns: repeat(2, 1fr); }
        .grid-cols-3 { grid-template-columns: repeat(3, 1fr); }
        
        .hidden { display: none; }
        
        .mb-4 { margin-bottom: 1rem; }
        .mb-8 { margin-bottom: 2rem; }
        .text-center { text-align: center; }
        .text-xl { font-size: 1.25rem; }
        .text-2xl { font-size: 1.5rem; }
        .font-bold { font-weight: 700; }
        .flex { display: flex; }
        .items-center { align-items: center; }
        .justify-between { justify-content: space-between; }
        .space-x-2 > * + * { margin-left: 0.5rem; }
        
        .chart-container {
            width: 100%;
            height: 300px;
        }
        
        .file-input {
            border: 2px dashed hsl(var(--border));
            border-radius: var(--radius);
            padding: 2rem;
            text-align: center;
            cursor: pointer;
            transition: border-color 0.2s;
        }
        
        .file-input:hover {
            border-color: hsl(var(--primary));
        }
        
        .select {
            background-color: hsl(var(--input));
            border: 1px solid hsl(var(--border));
            border-radius: var(--radius);
            padding: 0.5rem 0.75rem;
            color: hsl(var(--foreground));
        }
    </style>
</head>
<body>
    <div id="root"></div>

    <script>
        const { useState, useEffect, useCallback } = React;
        const { createRoot } = ReactDOM;

        // Vulnerability Dashboard Component
        function VulnerabilityDashboard() {
            const [vulnerabilities, setVulnerabilities] = useState([]);
            const [csvData, setCsvData] = useState([]);
            const [columnMapping, setColumnMapping] = useState({});
            const [step, setStep] = useState('upload');
            const [customerName, setCustomerName] = useState('');

            const handleFileUpload = (event) => {
                const file = event.target.files[0];
                if (file && file.type === 'text/csv') {
                    Papa.parse(file, {
                        complete: (results) => {
                            setCsvData(results.data);
                            setStep('mapping');
                        },
                        header: true,
                        skipEmptyLines: true
                    });
                }
            };

            const handleMappingComplete = (mapping) => {
                const mappedData = csvData.map((row, index) => ({
                    id: row[mapping.id] || \`vuln-\${index + 1}\`,
                    title: row[mapping.title] || 'Unknown Title',
                    severity: row[mapping.severity] || 'Unknown',
                    score: parseFloat(row[mapping.score]) || 0,
                    asset: row[mapping.asset] || 'Unknown Asset',
                    ipAddress: row[mapping.ipAddress] || '0.0.0.0',
                    protocol: row[mapping.protocol] || 'Unknown'
                }));
                setVulnerabilities(mappedData);
                setColumnMapping(mapping);
                setStep('dashboard');
            };

            const severityCount = vulnerabilities.reduce((acc, vuln) => {
                acc[vuln.severity] = (acc[vuln.severity] || 0) + 1;
                return acc;
            }, { Critical: 0, High: 0, Medium: 0, Low: 0, Unknown: 0 });

            if (step === 'upload') {
                return React.createElement('div', { className: 'container' },
                    React.createElement('div', { className: 'card' },
                        React.createElement('div', { className: 'card-header' },
                            React.createElement('h2', { className: 'card-title text-2xl text-center' }, '🛡️ Vulnerability Dashboard'),
                            React.createElement('p', { className: 'card-description text-center' }, 'Upload your CSV file to begin vulnerability analysis')
                        ),
                        React.createElement('div', { className: 'file-input' },
                            React.createElement('input', {
                                type: 'file',
                                accept: '.csv',
                                onChange: handleFileUpload,
                                className: 'input'
                            }),
                            React.createElement('p', { className: 'mb-4' }, 'Select a CSV file containing vulnerability data')
                        )
                    )
                );
            }

            if (step === 'mapping') {
                return React.createElement(ColumnMappingComponent, {
                    csvHeaders: Object.keys(csvData[0] || {}),
                    onMappingComplete: handleMappingComplete,
                    onBack: () => setStep('upload')
                });
            }

            return React.createElement('div', { className: 'container' },
                React.createElement('div', { className: 'mb-8' },
                    React.createElement('div', { className: 'flex items-center justify-between mb-4' },
                        React.createElement('h1', { className: 'text-2xl font-bold' }, '🛡️ Vulnerability Dashboard'),
                        React.createElement('div', { className: 'flex space-x-2' },
                            React.createElement('button', {
                                className: 'button button-secondary',
                                onClick: () => setStep('upload')
                            }, 'Load New Data'),
                            React.createElement('button', {
                                className: 'button button-secondary',
                                onClick: () => {
                                    setVulnerabilities([]);
                                    setStep('upload');
                                }
                            }, 'Clear Data')
                        )
                    )
                ),
                React.createElement(VulnerabilitySummary, { severityCount, totalVulnerabilities: vulnerabilities.length }),
                React.createElement('div', { className: 'grid grid-cols-2 mb-8' },
                    React.createElement(SeverityChart, { severityCount }),
                    React.createElement(TopVulnerabilitiesTable, { vulnerabilities, severity: 'Critical', title: 'Critical Vulnerabilities' })
                ),
                React.createElement('div', { className: 'grid grid-cols-2' },
                    React.createElement(TopVulnerabilitiesTable, { vulnerabilities, severity: 'High', title: 'High Vulnerabilities' }),
                    React.createElement(TopVulnerabilitiesTable, { vulnerabilities, severity: 'Medium', title: 'Medium Vulnerabilities' })
                )
            );
        }

        function ColumnMappingComponent({ csvHeaders, onMappingComplete, onBack }) {
            const [mapping, setMapping] = useState({
                id: '',
                title: '',
                severity: '',
                score: '',
                asset: '',
                ipAddress: '',
                protocol: ''
            });

            const handleSubmit = () => {
                onMappingComplete(mapping);
            };

            return React.createElement('div', { className: 'container' },
                React.createElement('div', { className: 'card' },
                    React.createElement('div', { className: 'card-header' },
                        React.createElement('h2', { className: 'card-title' }, 'Map CSV Columns'),
                        React.createElement('p', { className: 'card-description' }, 'Map your CSV columns to vulnerability data fields')
                    ),
                    React.createElement('div', { className: 'grid grid-cols-2' },
                        Object.keys(mapping).map(field =>
                            React.createElement('div', { key: field, className: 'mb-4' },
                                React.createElement('label', { className: 'block mb-2 font-medium' }, field.charAt(0).toUpperCase() + field.slice(1)),
                                React.createElement('select', {
                                    className: 'select',
                                    value: mapping[field],
                                    onChange: (e) => setMapping(prev => ({ ...prev, [field]: e.target.value }))
                                },
                                    React.createElement('option', { value: '' }, 'Select column...'),
                                    csvHeaders.map(header =>
                                        React.createElement('option', { key: header, value: header }, header)
                                    )
                                )
                            )
                        )
                    ),
                    React.createElement('div', { className: 'flex space-x-2' },
                        React.createElement('button', { className: 'button button-secondary', onClick: onBack }, 'Back'),
                        React.createElement('button', { className: 'button button-primary', onClick: handleSubmit }, 'Continue to Dashboard')
                    )
                )
            );
        }

        function VulnerabilitySummary({ severityCount, totalVulnerabilities }) {
            const criticalAndHigh = severityCount.Critical + severityCount.High;
            const riskLevel = criticalAndHigh > totalVulnerabilities * 0.3 ? 'High' : criticalAndHigh > totalVulnerabilities * 0.1 ? 'Medium' : 'Low';

            return React.createElement('div', { className: 'card mb-8' },
                React.createElement('div', { className: 'card-header' },
                    React.createElement('h2', { className: 'card-title' }, 'Summary'),
                    React.createElement('p', { className: 'card-description' }, 'Overview of vulnerability findings')
                ),
                React.createElement('div', { className: 'grid grid-cols-3' },
                    React.createElement('div', { className: 'text-center' },
                        React.createElement('div', { className: 'text-2xl font-bold mb-2' }, totalVulnerabilities),
                        React.createElement('p', null, 'Total Vulnerabilities')
                    ),
                    React.createElement('div', { className: 'text-center' },
                        React.createElement('div', { className: 'text-2xl font-bold mb-2' }, criticalAndHigh),
                        React.createElement('p', null, 'Critical & High')
                    ),
                    React.createElement('div', { className: 'text-center' },
                        React.createElement('span', { className: \`badge badge-\${riskLevel.toLowerCase()}\` }, riskLevel),
                        React.createElement('p', { className: 'mt-2' }, 'Risk Level')
                    )
                )
            );
        }

        function SeverityChart({ severityCount }) {
            const data = Object.entries(severityCount)
                .filter(([_, count]) => count > 0)
                .map(([severity, count]) => ({ severity, count }));

            return React.createElement('div', { className: 'card' },
                React.createElement('div', { className: 'card-header' },
                    React.createElement('h3', { className: 'card-title' }, 'Severity Distribution')
                ),
                React.createElement('div', { className: 'chart-container' },
                    data.length > 0 ? 
                        React.createElement('div', { className: 'grid' },
                            data.map(({ severity, count }) =>
                                React.createElement('div', { key: severity, className: 'flex items-center justify-between p-2' },
                                    React.createElement('span', { className: \`badge badge-\${severity.toLowerCase()}\` }, severity),
                                    React.createElement('span', { className: 'font-bold' }, count)
                                )
                            )
                        ) :
                        React.createElement('p', { className: 'text-center' }, 'No data to display')
                )
            );
        }

        function TopVulnerabilitiesTable({ vulnerabilities, severity, title }) {
            const filteredVulns = vulnerabilities
                .filter(v => v.severity === severity)
                .sort((a, b) => b.score - a.score)
                .slice(0, 10);

            return React.createElement('div', { className: 'card' },
                React.createElement('div', { className: 'card-header' },
                    React.createElement('h3', { className: 'card-title' }, title),
                    React.createElement('p', { className: 'card-description' }, \`Top 10 \${severity} severity vulnerabilities\`)
                ),
                React.createElement('div', null,
                    filteredVulns.length > 0 ?
                        React.createElement('table', { className: 'table' },
                            React.createElement('thead', null,
                                React.createElement('tr', null,
                                    React.createElement('th', null, 'ID'),
                                    React.createElement('th', null, 'Title'),
                                    React.createElement('th', null, 'Asset'),
                                    React.createElement('th', null, 'Score')
                                )
                            ),
                            React.createElement('tbody', null,
                                filteredVulns.map(vuln =>
                                    React.createElement('tr', { key: vuln.id },
                                        React.createElement('td', null, vuln.id),
                                        React.createElement('td', null, vuln.title.substring(0, 50) + (vuln.title.length > 50 ? '...' : '')),
                                        React.createElement('td', null, vuln.asset),
                                        React.createElement('td', null, vuln.score.toFixed(1))
                                    )
                                )
                            )
                        ) :
                        React.createElement('p', { className: 'text-center' }, \`No \${severity} vulnerabilities found\`)
                )
            );
        }

        // Initialize the application
        const root = createRoot(document.getElementById('root'));
        root.render(React.createElement(VulnerabilityDashboard));
    </script>
</body>
</html>`;

    const blob = new Blob([standaloneHtml], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `vulnerability-dashboard-standalone-${new Date().toISOString().split('T')[0]}.html`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  }, []);

  return { exportStandaloneHtml };
};