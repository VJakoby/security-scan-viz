import { useState, useEffect, useCallback } from 'react';
import { KEVCatalog, KEVMatch, Vulnerability } from '@/types/vulnerability';

const KEV_API_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const KEV_CACHE_KEY = 'kev-data';
const KEV_CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours in milliseconds

export const useKEVData = () => {
  const [kevData, setKevData] = useState<KEVCatalog | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchKEVData = useCallback(async () => {
    setLoading(true);
    setError(null);
    
    try {
      // Check cache first
      const cached = localStorage.getItem(KEV_CACHE_KEY);
      if (cached) {
        const { data, timestamp } = JSON.parse(cached);
        const isExpired = Date.now() - timestamp > KEV_CACHE_DURATION;
        
        if (!isExpired) {
          setKevData(data);
          setLoading(false);
          return;
        }
      }

      // Fetch fresh data
      const response = await fetch(KEV_API_URL);
      if (!response.ok) {
        throw new Error(`Failed to fetch KEV data: ${response.statusText}`);
      }
      
      const data: KEVCatalog = await response.json();
      setKevData(data);
      
      // Cache the data
      localStorage.setItem(KEV_CACHE_KEY, JSON.stringify({
        data,
        timestamp: Date.now()
      }));
      
    } catch (err) {
      console.error('Error fetching KEV data:', err);
      setError(err instanceof Error ? err.message : 'Failed to fetch KEV data');
    } finally {
      setLoading(false);
    }
  }, []);

  const findKEVMatches = useCallback((vulnerabilities: Vulnerability[]): KEVMatch[] => {
    if (!kevData) return [];
    
    const kevMap = new Map(kevData.vulnerabilities.map(kev => [kev.cveID, kev]));
    const matches: KEVMatch[] = [];
    
    vulnerabilities.forEach(vuln => {
      // Check if the vulnerability ID is a CVE ID or contains a CVE ID
      const cveRegex = /CVE-\d{4}-\d{4,}/i;
      let cveId = vuln.id;
      
      // Extract CVE from ID if it's in the format
      const cveMatch = vuln.id.match(cveRegex);
      if (cveMatch) {
        cveId = cveMatch[0].toUpperCase();
      }
      
      // Also check title for CVE IDs
      const titleCveMatch = vuln.title.match(cveRegex);
      if (titleCveMatch) {
        cveId = titleCveMatch[0].toUpperCase();
      }
      
      const kevEntry = kevMap.get(cveId);
      if (kevEntry) {
        matches.push({ vulnerability: vuln, kevEntry });
      }
    });
    
    return matches.sort((a, b) => b.vulnerability.score - a.vulnerability.score);
  }, [kevData]);

  useEffect(() => {
    fetchKEVData();
  }, [fetchKEVData]);

  return {
    kevData,
    loading,
    error,
    findKEVMatches,
    refetch: fetchKEVData
  };
};