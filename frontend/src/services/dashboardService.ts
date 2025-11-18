import { api } from './api';

export interface DashboardSummary {
  total_alerts: number;
  critical_alerts: number;
  high_alerts: number;
  medium_alerts: number;
  low_alerts: number;
  total_vulnerabilities: number;
  total_assets: number;
  compliance_score: number;
  risk_score: number;
  attack_paths: number;
}

export interface TrendData {
  date: string;
  alerts: number;
  vulnerabilities: number;
  risk_score: number;
}

export interface SeverityDistribution {
  severity: string;
  count: number;
}

export interface ComplianceStatus {
  framework: string;
  score: number;
  total_controls: number;
  passed_controls: number;
  failed_controls: number;
}

export interface TopVulnerability {
  id: string;
  name: string;
  severity: string;
  cvss_score: number;
  affected_assets_count: number;
  exploit_available: boolean;
}

export interface RecentAlert {
  id: string;
  title: string;
  severity: string;
  timestamp: string;
  status: string;
}

// Import the DashboardData type
import { DashboardData } from '@/types/dashboard';

const dashboardService = {
  getDashboardSummary: async (): Promise<DashboardSummary> => {
    try {
      const response = await api.get('/dashboard/summary');
      return response.data;
    } catch (error) {
      console.error('Error fetching dashboard summary:', error);
      throw error;
    }
  },

  getTrendData: async (timeframe: 'day' | 'week' | 'month' = 'week'): Promise<TrendData[]> => {
    try {
      const response = await api.get('/dashboard/trends', {
        params: { timeframe },
      });
      return response.data;
    } catch (error) {
      console.error('Error fetching trend data:', error);
      throw error;
    }
  },

  getSeverityDistribution: async (): Promise<SeverityDistribution[]> => {
    try {
      const response = await api.get('/dashboard/severity-distribution');
      return response.data;
    } catch (error) {
      console.error('Error fetching severity distribution:', error);
      throw error;
    }
  },

  getComplianceStatus: async (): Promise<ComplianceStatus[]> => {
    try {
      const response = await api.get('/dashboard/compliance-status');
      return response.data;
    } catch (error) {
      console.error('Error fetching compliance status:', error);
      throw error;
    }
  },

  getTopVulnerabilities: async (limit: number = 5): Promise<TopVulnerability[]> => {
    try {
      const response = await api.get('/dashboard/top-vulnerabilities', {
        params: { limit },
      });
      return response.data;
    } catch (error) {
      console.error('Error fetching top vulnerabilities:', error);
      throw error;
    }
  },

  getRecentAlerts: async (limit: number = 5): Promise<RecentAlert[]> => {
    try {
      const response = await api.get('/dashboard/recent-alerts', {
        params: { limit },
      });
      return response.data;
    } catch (error) {
      console.error('Error fetching recent alerts:', error);
      throw error;
    }
  },

  getAssetRiskDistribution: async (): Promise<any> => {
    try {
      const response = await api.get('/dashboard/asset-risk-distribution');
      return response.data;
    } catch (error) {
      console.error('Error fetching asset risk distribution:', error);
      throw error;
    }
  },

  getAttackSurfaceMetrics: async (): Promise<any> => {
    try {
      const response = await api.get('/dashboard/attack-surface-metrics');
      return response.data;
    } catch (error) {
      console.error('Error fetching attack surface metrics:', error);
      throw error;
    }
  },
};

// Add fetchDashboardData as a named export
export const fetchDashboardData = async (): Promise<DashboardData> => {
  try {
    const response = await api.get('/dashboard/');
    return response.data;
  } catch (error) {
    console.error('Error fetching dashboard data:', error);
    throw error;
  }
};

export default dashboardService;