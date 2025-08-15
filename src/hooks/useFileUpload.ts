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
      Papa.parse(file, {
        header: true,
        skipEmptyLines: true,
        complete: (results) => {
          if (results.errors.length > 0) {
            reject(new Error(results.errors[0].message));
            return;
          }
          
          const headers = results.meta.fields || [];
          const rows = results.data as VulnerabilityData[];
          
          resolve({ headers, rows });
        },
        error: (error) => {
          reject(new Error(error.message));
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