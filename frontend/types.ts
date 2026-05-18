
import React from 'react';

export type Severity = 'High' | 'Medium' | 'Low';

export interface Vulnerability {
  id: string;
  url: string;
  parameter: string;
  payload: string;
  type: string;
  severity: Severity;
  responseSnippet: string;
  fixRecommendation: string;
}

export interface ScanLog {
  id: string;
  timestamp: string;
  url: string;
  payload: string;
  status: number;
  method: string;
}

export type ScanType = 'Basic Fuzzing' | 'SQL Injection Test' | 'XSS Test' | 'Full Security Scan';

export interface ScanConfig {
  targetUrl: string;
  scanType: ScanType;
  depth: number;
  payloads: {
    sql: boolean;
    xss: boolean;
    longString: boolean;
    specialChar: boolean;
    custom: string;
  };
}

export interface NavItem {
  id: string;
  label: string;
  icon: React.ReactNode;
}
