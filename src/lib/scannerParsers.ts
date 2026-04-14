import { Vulnerability, VulnerabilityData } from '@/types/vulnerability';

export type DetectedFormat =
  | 'generic'
  | 'nessus-csv'
  | 'nessus-xml'
  | 'nexpose-csv'
  | 'nexpose-xml'
  | 'nmap';

export interface NormalizedImport {
  vulnerabilities: Vulnerability[];
  detectedFormat: DetectedFormat;
  scanner: string;
  reportName?: string;
}

const EMPTY_VALUES = new Set(['', 'n/a', 'na', 'none', 'null', 'undefined', '-']);

const getString = (value: unknown): string => {
  if (value === undefined || value === null) {
    return '';
  }

  return String(value).trim();
};

const isMeaningful = (value: string): boolean => !EMPTY_VALUES.has(value.trim().toLowerCase());

const firstNonEmpty = (...values: Array<unknown>): string => {
  for (const value of values) {
    const text = getString(value);
    if (isMeaningful(text)) {
      return text;
    }
  }

  return '';
};

const getFieldValue = (row: VulnerabilityData, candidates: string[]): string => {
  const lowered = new Map(Object.keys(row).map((key) => [key.toLowerCase(), key]));

  for (const candidate of candidates) {
    const match = lowered.get(candidate.toLowerCase());
    if (match) {
      const value = getString(row[match]);
      if (value) {
        return value;
      }
    }
  }

  return '';
};

const parseScore = (...values: Array<unknown>): number => {
  for (const value of values) {
    const text = getString(value);
    if (!text) {
      continue;
    }

    const match = text.match(/-?\d+(?:\.\d+)?/);
    if (match) {
      return Number.parseFloat(match[0]);
    }
  }

  return 0;
};

export const normalizeSeverity = (severity: unknown, score?: number): Vulnerability['severity'] => {
  const text = getString(severity).toLowerCase();

  if (text.includes('critical') || text === '4' || text === 'severe') return 'Critical';
  if (text.includes('high') || text === '3') return 'High';
  if (text.includes('medium') || text.includes('moderate') || text === '2') return 'Medium';
  if (text.includes('low') || text === '1') return 'Low';
  if (text.includes('info') || text.includes('none') || text === '0') return 'Low';

  if (typeof score === 'number') {
    if (score >= 9) return 'Critical';
    if (score >= 7) return 'High';
    if (score >= 4) return 'Medium';
    if (score > 0) return 'Low';
  }

  return 'Unknown';
};

const parseCves = (...values: Array<unknown>): string[] => {
  const found = new Set<string>();

  values.forEach((value) => {
    const text = getString(value);
    if (!text) {
      return;
    }

    const matches = text.match(/CVE-\d{4}-\d{4,}/gi);
    if (matches) {
      matches.forEach((match) => found.add(match.toUpperCase()));
      return;
    }

    text
      .split(/[\n,;|]/)
      .map((part) => part.trim())
      .filter(Boolean)
      .forEach((part) => {
        if (/^[A-Z]+-\d{4}-\d{4,}$/i.test(part)) {
          found.add(part.toUpperCase());
        }
      });
  });

  return Array.from(found);
};

const getFileBaseName = (fileName: string): string =>
  fileName.replace(/\.[^.]+$/, '').replace(/[_-]+/g, ' ').trim();

const buildFindingKey = (vuln: Vulnerability): string =>
  [
    vuln.id,
    vuln.title,
    vuln.asset,
    vuln.ipAddress,
    vuln.port || '',
    vuln.protocol || '',
    vuln.service || '',
  ]
    .map((value) => getString(value).toLowerCase())
    .join('|');

const uniqueVulnerabilities = (vulnerabilities: Vulnerability[]): Vulnerability[] => {
  const deduped = new Map<string, Vulnerability>();

  vulnerabilities.forEach((vulnerability) => {
    const findingKey = vulnerability.findingKey || buildFindingKey(vulnerability);
    const next = { ...vulnerability, findingKey };
    const existing = deduped.get(findingKey);

    if (!existing) {
      deduped.set(findingKey, next);
      return;
    }

    if ((next.score || 0) >= (existing.score || 0)) {
      deduped.set(findingKey, {
        ...existing,
        ...next,
        cves: Array.from(new Set([...(existing.cves || []), ...(next.cves || [])])),
        description: firstNonEmpty(next.description, existing.description),
        solution: firstNonEmpty(next.solution, existing.solution),
      });
    }
  });

  return Array.from(deduped.values());
};

export const detectScannerFormat = (headers: string[]): DetectedFormat => {
  const normalizedHeaders = headers.map((header) => header.toLowerCase());

  const has = (...patterns: string[]) =>
    patterns.every((pattern) => normalizedHeaders.some((header) => header.includes(pattern)));

  if (has('plugin id', 'plugin name') || has('host', 'cves')) {
    return 'nessus-csv';
  }

  if (
    has('asset ip address', 'vulnerability title') ||
    has('asset name', 'risk score') ||
    has('asset names', 'vulnerability id')
  ) {
    return 'nexpose-csv';
  }

  return 'generic';
};

const normalizeNessusRow = (row: VulnerabilityData, fileName: string): Vulnerability => {
  const score = parseScore(
    getFieldValue(row, ['CVSS v3 Score', 'CVSS v2 Score', 'CVSS Score', 'Score', 'Risk Score'])
  );
  const title = firstNonEmpty(
    getFieldValue(row, ['Plugin Name', 'Name', 'Title']),
    getFieldValue(row, ['Synopsis']),
    'Unnamed vulnerability'
  );
  const id = firstNonEmpty(
    getFieldValue(row, ['Plugin ID']),
    parseCves(getFieldValue(row, ['CVEs', 'CVE']))[0],
    title
  );

  const vulnerability: Vulnerability = {
    id,
    title,
    asset: firstNonEmpty(getFieldValue(row, ['Host', 'Hostname', 'Asset'])),
    ipAddress: firstNonEmpty(getFieldValue(row, ['IP', 'IP Address'])),
    severity: normalizeSeverity(getFieldValue(row, ['Severity', 'Risk']), score),
    score,
    scanner: 'Nessus',
    sourceFormat: 'nessus-csv',
    sourceFile: fileName,
    description: firstNonEmpty(
      getFieldValue(row, ['Description', 'Synopsis', 'Plugin Output']),
      title
    ),
    solution: getFieldValue(row, ['Solution', 'See Also']),
    cves: parseCves(getFieldValue(row, ['CVEs', 'CVE']), title),
    port: getFieldValue(row, ['Port']),
    protocol: getFieldValue(row, ['Protocol']),
    service: firstNonEmpty(getFieldValue(row, ['Service', 'Service Name']), getFieldValue(row, ['Protocol'])),
  };

  return { ...vulnerability, findingKey: buildFindingKey(vulnerability) };
};

const normalizeNexposeRow = (row: VulnerabilityData, fileName: string): Vulnerability => {
  const score = parseScore(
    getFieldValue(row, ['CVSS v3 Score', 'CVSS Score', 'Risk Score', 'Risk']),
    getFieldValue(row, ['Severity Score'])
  );
  const title = firstNonEmpty(
    getFieldValue(row, ['Vulnerability Title', 'Title', 'Vulnerability', 'Vulnerability Name']),
    getFieldValue(row, ['Proof']),
    'Unnamed vulnerability'
  );
  const cves = parseCves(
    getFieldValue(row, ['Vulnerability CVE IDs', 'CVE', 'CVE IDs']),
    title
  );
  const id = firstNonEmpty(
    getFieldValue(row, ['Vulnerability ID', 'Vulnerability Check ID']),
    cves[0],
    title
  );

  const vulnerability: Vulnerability = {
    id,
    title,
    asset: firstNonEmpty(
      getFieldValue(row, ['Asset Name', 'Asset Names', 'Hostname', 'Host Name', 'Node Name'])
    ),
    ipAddress: firstNonEmpty(getFieldValue(row, ['Asset IP Address', 'IP Address', 'Address'])),
    severity: normalizeSeverity(
      getFieldValue(row, ['Severity', 'Risk', 'Risk Rating', 'Vulnerability Severity']),
      score
    ),
    score,
    scanner: 'Nexpose',
    sourceFormat: 'nexpose-csv',
    sourceFile: fileName,
    description: firstNonEmpty(
      getFieldValue(row, ['Proof', 'Description', 'Finding Details', 'Vulnerability Description']),
      title
    ),
    solution: getFieldValue(row, ['Solution', 'Fix', 'Remediation']),
    cves,
    port: getFieldValue(row, ['Port']),
    protocol: getFieldValue(row, ['Protocol']),
    service: getFieldValue(row, ['Service', 'Service Name']),
  };

  return { ...vulnerability, findingKey: buildFindingKey(vulnerability) };
};

export const normalizeScannerRows = (
  rows: VulnerabilityData[],
  headers: string[],
  fileName: string
): NormalizedImport | null => {
  const detectedFormat = detectScannerFormat(headers);

  if (detectedFormat === 'generic') {
    return null;
  }

  const vulnerabilities = rows
    .map((row) =>
      detectedFormat === 'nessus-csv'
        ? normalizeNessusRow(row, fileName)
        : normalizeNexposeRow(row, fileName)
    )
    .filter((row) => row.title || row.id || row.asset || row.ipAddress);

  if (vulnerabilities.length === 0) {
    return null;
  }

  return {
    vulnerabilities: uniqueVulnerabilities(vulnerabilities),
    detectedFormat,
    scanner: detectedFormat.startsWith('nessus') ? 'Nessus' : 'Nexpose',
    reportName: getFileBaseName(fileName),
  };
};

const getElements = (root: ParentNode, localNames: string[]): Element[] =>
  Array.from(root.getElementsByTagName('*')).filter((element) =>
    localNames.includes(element.localName)
  );

const getFirstElement = (root: ParentNode, localNames: string[]): Element | undefined =>
  getElements(root, localNames)[0];

const getElementText = (root: ParentNode, localNames: string[]): string =>
  getFirstElement(root, localNames)?.textContent?.trim() || '';

const getDefinitionMap = (document: Document): Map<string, Partial<Vulnerability>> => {
  const definitions = new Map<string, Partial<Vulnerability>>();

  getElements(document, ['vulnerability', 'VulnerabilityDefinition']).forEach((element) => {
    const id = firstNonEmpty(element.getAttribute('id'), element.getAttribute('vulnid'));
    const title = firstNonEmpty(
      element.getAttribute('title'),
      getElementText(element, ['title'])
    );

    if (!id && !title) {
      return;
    }

    definitions.set(id || title, {
      id: id || title,
      title: title || id || 'Unnamed vulnerability',
      score: parseScore(
        element.getAttribute('cvssScore'),
        element.getAttribute('cvssscore'),
        getElementText(element, ['cvssScore', 'cvssscore', 'cvssv3', 'cvssv2'])
      ),
      description: firstNonEmpty(
        getElementText(element, ['description', 'paragraph']),
        getElementText(element, ['proof'])
      ),
      solution: firstNonEmpty(
        getElementText(element, ['solution', 'fix', 'recommendation'])
      ),
      cves: parseCves(
        getElementText(element, ['reference', 'references']),
        element.getAttribute('cve'),
        getElementText(element, ['cve'])
      ),
    });
  });

  return definitions;
};

const parseNessusXml = (document: Document, fileName: string): NormalizedImport | null => {
  const reportHosts = getElements(document, ['ReportHost']);
  if (reportHosts.length === 0) {
    return null;
  }

  const vulnerabilities: Vulnerability[] = [];

  reportHosts.forEach((reportHost) => {
    const hostName = firstNonEmpty(reportHost.getAttribute('name'));
    const hostProperties = getFirstElement(reportHost, ['HostProperties']);
    const hostIp =
      getElements(hostProperties || reportHost, ['tag']).find(
        (tag) => tag.getAttribute('name') === 'host-ip'
      )?.textContent?.trim() || '';
    const fqdn =
      getElements(hostProperties || reportHost, ['tag']).find(
        (tag) => tag.getAttribute('name') === 'host-fqdn'
      )?.textContent?.trim() || '';

    getElements(reportHost, ['ReportItem']).forEach((item) => {
      const score = parseScore(
        getElementText(item, ['cvss3_base_score', 'cvss_base_score']),
        item.getAttribute('severity')
      );
      const title = firstNonEmpty(item.getAttribute('pluginName'), getElementText(item, ['synopsis']));
      const cves = parseCves(getElementText(item, ['cve']), title);
      const vulnerability: Vulnerability = {
        id: firstNonEmpty(item.getAttribute('pluginID'), cves[0], title),
        title: title || 'Unnamed vulnerability',
        asset: firstNonEmpty(fqdn, hostName, hostIp),
        ipAddress: hostIp,
        severity: normalizeSeverity(item.getAttribute('severity'), score),
        score,
        scanner: 'Nessus',
        sourceFormat: 'nessus-xml',
        sourceFile: fileName,
        description: firstNonEmpty(
          getElementText(item, ['description', 'synopsis', 'plugin_output']),
          title
        ),
        solution: getElementText(item, ['solution']),
        cves,
        port: getString(item.getAttribute('port')),
        protocol: getString(item.getAttribute('protocol')),
        service: firstNonEmpty(getString(item.getAttribute('svc_name')), getString(item.getAttribute('protocol'))),
      };

      vulnerabilities.push({ ...vulnerability, findingKey: buildFindingKey(vulnerability) });
    });
  });

  if (vulnerabilities.length === 0) {
    return null;
  }

  return {
    vulnerabilities: uniqueVulnerabilities(vulnerabilities),
    detectedFormat: 'nessus-xml',
    scanner: 'Nessus',
    reportName: getFileBaseName(fileName),
  };
};

const parseNexposeXml = (document: Document, fileName: string): NormalizedImport | null => {
  const nodes = getElements(document, ['node']);
  if (nodes.length === 0) {
    return null;
  }

  const definitionMap = getDefinitionMap(document);
  const vulnerabilities: Vulnerability[] = [];

  nodes.forEach((node) => {
    const ipAddress = firstNonEmpty(node.getAttribute('address'));
    const asset = firstNonEmpty(
      getElementText(node, ['name']),
      getElementText(node, ['hostname']),
      node.getAttribute('site-name'),
      ipAddress
    );

    getElements(node, ['test', 'vulnerability']).forEach((finding) => {
      const id = firstNonEmpty(
        finding.getAttribute('id'),
        finding.getAttribute('vulnerability-id'),
        finding.getAttribute('vulnid')
      );

      const definition = definitionMap.get(id) || {};
      const endpoint = finding.closest('endpoint');
      const serviceElement = finding.closest('service');
      const score = parseScore(
        finding.getAttribute('cvssScore'),
        definition.score,
        finding.getAttribute('riskScore')
      );
      const title = firstNonEmpty(
        finding.getAttribute('title'),
        definition.title,
        getElementText(finding, ['paragraph'])
      );
      const cves = parseCves(
        finding.getAttribute('cve'),
        getElementText(finding, ['cve', 'reference']),
        definition.cves?.join(','),
        title
      );

      const vulnerability: Vulnerability = {
        id: firstNonEmpty(id, cves[0], title),
        title: title || 'Unnamed vulnerability',
        asset,
        ipAddress,
        severity: normalizeSeverity(
          finding.getAttribute('severity') || finding.getAttribute('status'),
          score
        ),
        score,
        scanner: 'Nexpose',
        sourceFormat: 'nexpose-xml',
        sourceFile: fileName,
        description: firstNonEmpty(
          getElementText(finding, ['paragraph', 'proof']),
          definition.description,
          title
        ),
        solution: firstNonEmpty(
          getElementText(finding, ['solution', 'fix']),
          definition.solution
        ),
        cves,
        port: firstNonEmpty(endpoint?.getAttribute('port')),
        protocol: firstNonEmpty(endpoint?.getAttribute('protocol')),
        service: firstNonEmpty(
          serviceElement?.getAttribute('name'),
          endpoint?.getAttribute('protocol')
        ),
      };

      vulnerabilities.push({ ...vulnerability, findingKey: buildFindingKey(vulnerability) });
    });
  });

  if (vulnerabilities.length === 0) {
    return null;
  }

  return {
    vulnerabilities: uniqueVulnerabilities(vulnerabilities),
    detectedFormat: 'nexpose-xml',
    scanner: 'Nexpose',
    reportName: getFileBaseName(fileName),
  };
};

export const parseXmlScan = (content: string, fileName: string): NormalizedImport | null => {
  const parser = new DOMParser();
  const document = parser.parseFromString(content, 'application/xml');

  if (document.querySelector('parsererror')) {
    throw new Error('The XML file could not be parsed.');
  }

  const rootName = document.documentElement.localName;

  if (rootName === 'NessusClientData_v2') {
    return parseNessusXml(document, fileName);
  }

  if (rootName === 'NexposeReport' || rootName === 'NeXposeSimpleXML') {
    return parseNexposeXml(document, fileName);
  }

  return null;
};

export const finalizeGenericVulnerability = (vulnerability: Vulnerability): Vulnerability => ({
  ...vulnerability,
  findingKey: vulnerability.findingKey || buildFindingKey(vulnerability),
  cves: Array.from(new Set(vulnerability.cves || [])),
});

export const uniqueImportedVulnerabilities = uniqueVulnerabilities;
