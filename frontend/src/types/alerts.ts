export interface Alert {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  source: string;
  timestamp: string;
  status: 'new' | 'acknowledged' | 'resolved' | 'dismissed';
  asset_id?: string;
  asset_name?: string;
  attack_technique?: string;
  attack_tactic?: string;
  mitre_id?: string;
  remediation_steps?: string[];
  related_alerts?: string[];
}

export enum AlertSeverity {
  Low = 'low',
  Medium = 'medium',
  High = 'high',
  Critical = 'critical',
  Info = 'info'
}

export enum AlertStatus {
  New = 'new',
  Acknowledged = 'acknowledged',
  Resolved = 'resolved',
  Dismissed = 'dismissed'
}

export interface AlertFilters {
  severity?: string[];
  status?: string[];
  source?: string[];
  dateRange?: {
    start: string;
    end: string;
  };
  search?: string;
}

export interface AlertsResponse {
  alerts: Alert[];
  total: number;
  page: number;
  limit: number;
}