import { useState, useCallback } from 'react';
import Papa from 'papaparse';
import * as XLSX from 'xlsx';
import { ImportInfo, Vulnerability, VulnerabilityData } from '@/types/vulnerability';
import { parseNmapFile } from '@/hooks/useNmapParser';
import {
  finalizeGenericVulnerability,
  normalizeScannerRows,
  normalizeSeverity,
  parseXmlScan,
  uniqueImportedVulnerabilities,
} from '@/lib/scannerParsers';

export interface ParsedData {
  headers: string[];
  rows: VulnerabilityData[];
  normalizedVulnerabilities?: Vulnerability[];
  importInfo?: ImportInfo;
}

export const useFileUpload = () => {
  const [isLoading, setIsLoading] = useState(false);
  const [progress, setProgress] = useState(0);
  const [progressText, setProgressText] = useState('');

  const parseCSV = useCallback((file: File): Promise<ParsedData> => {
    return new Promise((resolve, reject) => {
      console.log('Starting CSV parse for file:', file.name);
      
      Papa.parse<VulnerabilityData>(file, {
        header: true,
        skipEmptyLines: true,
        quoteChar: '"',
        escapeChar: '"',
        delimiter: ',',
        transform: (value: string) => {
          return value?.trim() || '';
        },
        complete: (results) => {
          console.log('Papa Parse results:', {
            data: results.data?.length,
            errors: results.errors?.length,
            meta: results.meta
          });
          
          // Log first few rows for debugging
          if (results.data && results.data.length > 0) {
            console.log('First row sample:', results.data[0]);
          }
          
          // Handle errors more gracefully - only reject on critical errors
          const criticalErrors = results.errors.filter(error => 
            error.type === 'Delimiter' || error.type === 'Quotes'
          );
          
          if (criticalErrors.length > 0) {
            console.error('Critical CSV parsing errors:', criticalErrors);
            reject(new Error(`CSV parsing failed: ${criticalErrors[0].message}`));
            return;
          }
          
          // Log non-critical errors but continue
          if (results.errors.length > 0) {
            console.warn('Non-critical CSV parsing errors:', results.errors);
          }
          
          const headers = results.meta.fields || [];
          const rows = results.data;
          
          console.log(`Successfully parsed CSV: ${headers.length} headers, ${rows.length} rows`);
          resolve({ headers, rows });
        },
        error: (error) => {
          console.error('Papa Parse error:', error);
          reject(new Error(`CSV parsing error: ${error.message}`));
        }
      });
    });
  }, []);

  const parseExcel = useCallback((file: File): Promise<ParsedData> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      
      reader.onload = (e) => {
        try {
          const data = new Uint8Array(e.target?.result as ArrayBuffer);
          const workbook = XLSX.read(data, { type: 'array' });
          const firstSheetName = workbook.SheetNames[0];
          const worksheet = workbook.Sheets[firstSheetName];
          
          const jsonData = XLSX.utils.sheet_to_json(worksheet, { defval: '' });
          
          if (jsonData.length === 0) {
            resolve({ headers: [], rows: [] });
            return;
          }
          
          const headers = Object.keys(jsonData[0] as object);
          const rows = jsonData as VulnerabilityData[];
          
          resolve({ headers, rows });
        } catch (error) {
          reject(new Error(`Error parsing Excel file: ${error}`));
        }
      };
      
      reader.onerror = () => {
        reject(new Error('Error reading file'));
      };
      
      reader.readAsArrayBuffer(file);
    });
  }, []);

  const normalizeNmapRows = useCallback((rows: VulnerabilityData[], file: File): ParsedData => {
    const normalizedVulnerabilities = uniqueImportedVulnerabilities(
      rows.map((row, index) => finalizeGenericVulnerability({
        id: row['Title']?.toString() || `nmap-${index + 1}`,
        title: row['Title']?.toString() || row['Service']?.toString() || `Open port ${row['Port'] || ''}`,
        asset: row['Host']?.toString() || row['IP']?.toString() || 'Unknown',
        ipAddress: row['IP']?.toString() || '',
        severity: normalizeSeverity(row['Severity']),
        score: Number.parseFloat(row['Score']?.toString() || '0') || 0,
        scanner: 'Nmap',
        sourceFormat: 'nmap',
        sourceFile: file.name,
        description: row['Scripts']?.toString() || row['Version']?.toString() || '',
        solution: '',
        cves: [],
        port: row['Port']?.toString() || '',
        protocol: row['Protocol']?.toString() || '',
        service: row['Service']?.toString() || '',
      }))
    );

    return {
      headers: Object.keys(rows[0] || {}),
      rows,
      normalizedVulnerabilities,
      importInfo: {
        detectedFormat: 'nmap',
        scanner: 'Nmap',
        fileName: file.name,
        recordCount: normalizedVulnerabilities.length,
        reportName: file.name.replace(/\.[^.]+$/, ''),
        autoMapped: true,
      },
    };
  }, []);

  const uploadFile = useCallback(async (file: File): Promise<ParsedData> => {
    setIsLoading(true);
    setProgress(0);
    setProgressText('Reading file...');

    try {
      let result: ParsedData;
      
      if (file.name.toLowerCase().endsWith('.csv')) {
        setProgressText('Parsing CSV...');
        setProgress(50);
        result = await parseCSV(file);
      } else if (file.name.match(/\.(xlsx|xls)$/i)) {
        setProgressText('Parsing Excel...');
        setProgress(50);
        result = await parseExcel(file);
      } else if (file.name.match(/\.(nessus|xml)$/i)) {
        setProgressText('Parsing XML scan...');
        setProgress(50);
        const text = await file.text();
        const normalized = parseXmlScan(text, file.name);

        if (!normalized) {
          throw new Error('Unsupported XML format. Upload a Nessus .nessus file or a Nexpose XML export.');
        }

        result = {
          headers: [],
          rows: [],
          normalizedVulnerabilities: normalized.vulnerabilities,
          importInfo: {
            detectedFormat: normalized.detectedFormat,
            scanner: normalized.scanner,
            fileName: file.name,
            recordCount: normalized.vulnerabilities.length,
            reportName: normalized.reportName,
            autoMapped: true,
          },
        };
      } else if (file.name.toLowerCase().endsWith('.nmap')) {
        setProgressText('Parsing Nmap output...');
        setProgress(50);
        const text = await file.text();
        result = normalizeNmapRows(parseNmapFile(text).rows, file);
      } else {
        throw new Error('Unsupported file format. Please select CSV, Excel, Nessus/Nexpose XML, or .nmap data.');
      }

      if (!result.normalizedVulnerabilities && result.rows.length > 0) {
        const normalized = normalizeScannerRows(result.rows, result.headers, file.name);
        if (normalized) {
          result = {
            ...result,
            normalizedVulnerabilities: normalized.vulnerabilities,
            importInfo: {
              detectedFormat: normalized.detectedFormat,
              scanner: normalized.scanner,
              fileName: file.name,
              recordCount: normalized.vulnerabilities.length,
              reportName: normalized.reportName,
              autoMapped: true,
            },
          };
        }
      }

      setProgress(100);
      const loadedCount = result.normalizedVulnerabilities?.length ?? result.rows.length;
      setProgressText(`Loaded ${loadedCount} records successfully!`);
      
      return result;
    } finally {
      setTimeout(() => {
        setIsLoading(false);
        setProgress(0);
        setProgressText('');
      }, 1000);
    }
  }, [normalizeNmapRows, parseCSV, parseExcel]);

  return {
    uploadFile,
    isLoading,
    progress,
    progressText
  };
};
