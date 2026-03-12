export type Platform = 'hackerone' | 'bugcrowd' | 'intigriti' | 'other';
export type Schedule = 'daily' | 'weekly' | 'biweekly' | 'monthly';

export interface Program {
  name: string;
  platform: Platform;
  scopeFile: string;
  profile: 'quick' | 'standard' | 'deep' | 'stealth';
  schedule: Schedule;
  auth?: string;
  lastScan?: string;
  enabled?: boolean;
}

export interface EscalationItem {
  url: string;
  reason: 'captcha' | '2fa-required' | 'ambiguous-finding' | 'rate-limited' | 'auth-required';
  type?: string;
  confidence?: string;
  findingId?: string;
  timestamp: string;
}

export interface EscalationQueueData {
  target: string;
  scanDate: string;
  completed: number;
  needsHuman: number;
  blocked: EscalationItem[];
}

export interface HuntSummary {
  programs: number;
  findings: { high: number; medium: number; low: number };
  escalations: number;
  duration: string;
  scannedAt: string;
}
