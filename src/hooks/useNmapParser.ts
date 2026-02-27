import { VulnerabilityData } from '@/types/vulnerability';
import { ParsedData } from '@/hooks/useFileUpload';

interface NmapHost {
  hostname: string;
  ip: string;
  ports: NmapPort[];
}

interface NmapPort {
  port: string;
  protocol: string;
  state: string;
  service: string;
  version: string;
  scripts: string[];
}

export const parseNmapFile = (content: string): ParsedData => {
  const hosts: NmapHost[] = [];
  const lines = content.split('\n');

  let currentHost: NmapHost | null = null;
  let inPortSection = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Match "Nmap scan report for hostname (ip)" or "Nmap scan report for ip"
    const hostMatch = line.match(/^Nmap scan report for\s+(.+?)(?:\s+\(([^)]+)\))?$/);
    if (hostMatch) {
      if (currentHost) hosts.push(currentHost);
      const firstPart = hostMatch[1].trim();
      const secondPart = hostMatch[2]?.trim();
      currentHost = {
        hostname: secondPart ? firstPart : firstPart,
        ip: secondPart || firstPart,
        ports: [],
      };
      inPortSection = false;
      continue;
    }

    if (!currentHost) continue;

    // Detect start of port table
    if (line.match(/^PORT\s+STATE\s+SERVICE/)) {
      inPortSection = true;
      continue;
    }

    // End of port section on empty line or new section
    if (inPortSection && (line.trim() === '' || line.match(/^[A-Z]/))) {
      // Check if it's a port line first
      const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$/);
      if (!portMatch) {
        inPortSection = false;
      }
    }

    // Parse port lines: "22/tcp open ssh OpenSSH 8.9p1..."
    if (inPortSection) {
      const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+(\S+)\s+(\S+)(?:\s+(.*))?$/);
      if (portMatch) {
        currentHost.ports.push({
          port: portMatch[1],
          protocol: portMatch[2],
          state: portMatch[3],
          service: portMatch[4],
          version: portMatch[5]?.trim() || '',
          scripts: [],
        });
        continue;
      }
    }

    // Capture NSE script output (lines starting with |)
    if (line.startsWith('|') && currentHost.ports.length > 0) {
      const lastPort = currentHost.ports[currentHost.ports.length - 1];
      lastPort.scripts.push(line.replace(/^\|[-_ ]?\s?/, '').trim());
    }
  }

  // Push last host
  if (currentHost) hosts.push(currentHost);

  // Convert to flat rows
  const rows: VulnerabilityData[] = [];

  for (const host of hosts) {
    if (host.ports.length === 0) {
      // Host with no open ports – still include it
      rows.push({
        'Host': host.hostname,
        'IP': host.ip,
        'Port': '',
        'Protocol': '',
        'State': 'up (no open ports)',
        'Service': '',
        'Version': '',
        'Scripts': '',
        'Severity': 'Low',
        'Title': `Host ${host.hostname} - no open ports detected`,
      });
    } else {
      for (const port of host.ports) {
        const title = port.version
          ? `${port.service} ${port.version} on port ${port.port}/${port.protocol}`
          : `${port.service} on port ${port.port}/${port.protocol}`;

        rows.push({
          'Host': host.hostname,
          'IP': host.ip,
          'Port': port.port,
          'Protocol': port.protocol,
          'State': port.state,
          'Service': port.service,
          'Version': port.version,
          'Scripts': port.scripts.join('\n'),
          'Severity': 'Low',
          'Title': title,
        });
      }
    }
  }

  const headers = ['Host', 'IP', 'Port', 'Protocol', 'State', 'Service', 'Version', 'Scripts', 'Severity', 'Title'];

  return { headers, rows };
};
