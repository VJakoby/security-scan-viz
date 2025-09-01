import { useState, useCallback } from 'react';
import Papa from 'papaparse';
import * as XLSX from 'xlsx';
import { VulnerabilityData } from '@/types/vulnerability';

export interface ParsedData {
  headers: string[];
  rows: VulnerabilityData[];
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
      } else {
        throw new Error('Unsupported file format. Please select a CSV or Excel file.');
      }

      setProgress(100);
      setProgressText(`Loaded ${result.rows.length} rows successfully!`);
      
      return result;
    } catch (error) {
      throw error;
    } finally {
      setTimeout(() => {
        setIsLoading(false);
        setProgress(0);
        setProgressText('');
      }, 1000);
    }
  }, [parseCSV, parseExcel]);

  return {
    uploadFile,
    isLoading,
    progress,
    progressText
  };
};