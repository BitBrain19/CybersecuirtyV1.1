// Import AlertSeverity from alerts module to avoid duplication
import { AlertSeverity } from './alerts';

export interface DashboardData {
  securityScore: number;
  securityScoreTrend: number;
  vulnerabilitiesCount: number;
  vulnerabilitiesTrend: number;
  attackPathsCount: number;
  attackPathsTrend: number;
  alertsCount: number;
  alertsTrend: number;
  criticalVulnerabilities: number;
  vulnerabilitiesByType: {
    category: string;
    count: number;
  }[];
  vulnerabilityDistribution: {
    name: string;
    value: number;
  }[];
  alertsOverTime: {
    date: string;
    count: number;
  }[];
  recentAlerts: {
    id: string;
    title: string;
    description: string;
    severity: AlertSeverity;
    timestamp: string;
    status: 'new' | 'acknowledged' | 'resolved';
  }[];
  topVulnerabilities: {
    id: string;
    name: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    affectedAssets: number;
    discoveredAt: string;
  }[];
  systemHealth: {
    cpu: number;
    memory: number;
    storage: number;
    lastUpdated: string;
  };
}