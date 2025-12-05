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

import mlService from './mlService';

const dashboardService = {
  getDashboardSummary: async (): Promise<DashboardSummary> => {
    try {
      // Fetch stats, alerts, compliance, and attack paths
      const [statsResponse, alertsResponse, complianceResponse, attackPathsResponse] = await Promise.all([
        api.get('/stats'),
        api.get('/alerts?active_only=true'),
        mlService.assessCompliance('NIST'),
        mlService.getAttackPaths()
      ]);
      
      const stats = statsResponse.data;
      const alerts = alertsResponse.data;
      const compliance = complianceResponse;
      // attackPathsResponse can be a list or single graph object depending on backend
      const attackPathsCount = Array.isArray(attackPathsResponse) ? attackPathsResponse.length : (attackPathsResponse.paths ? attackPathsResponse.paths.length : 0);
      
      // Calculate metrics from real data
      const criticalAlerts = alerts.filter((a: any) => a.severity === 'critical').length;
      const highAlerts = alerts.filter((a: any) => a.severity === 'high').length;
      const mediumAlerts = alerts.filter((a: any) => a.severity === 'medium').length;
      const lowAlerts = alerts.filter((a: any) => a.severity === 'low').length;

      return {
        total_alerts: alerts.length,
        critical_alerts: criticalAlerts,
        high_alerts: highAlerts,
        medium_alerts: mediumAlerts,
        low_alerts: lowAlerts,
        total_vulnerabilities: 0, // Not exposed in stats yet
        total_assets: 0, // Not exposed in stats yet
        compliance_score: compliance.score || 0,
        risk_score: 100 - (criticalAlerts * 10 + highAlerts * 5),
        attack_paths: attackPathsCount
      };
    } catch (error) {
      console.error('Error fetching dashboard summary:', error);
      throw error;
    }
  },

  getTrendData: async (timeframe: 'day' | 'week' | 'month' = 'week'): Promise<TrendData[]> => {
    // Mocking trend data as backend doesn't support history API yet
    return [
      { date: '2023-11-01', alerts: 10, vulnerabilities: 5, risk_score: 20 },
      { date: '2023-11-02', alerts: 15, vulnerabilities: 4, risk_score: 25 },
      { date: '2023-11-03', alerts: 8, vulnerabilities: 6, risk_score: 18 },
      { date: '2023-11-04', alerts: 12, vulnerabilities: 5, risk_score: 22 },
      { date: '2023-11-05', alerts: 20, vulnerabilities: 8, risk_score: 35 },
    ];
  },

  getSeverityDistribution: async (): Promise<SeverityDistribution[]> => {
    try {
      const response = await api.get('/alerts?active_only=true');
      const alerts = response.data;
      
      const distribution = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0
      };
      
      alerts.forEach((a: any) => {
        if (distribution[a.severity as keyof typeof distribution] !== undefined) {
          distribution[a.severity as keyof typeof distribution]++;
        }
      });

      return Object.entries(distribution).map(([severity, count]) => ({
        severity,
        count
      }));
    } catch (error) {
      console.error('Error fetching severity distribution:', error);
      return [];
    }
  },

  getComplianceStatus: async (): Promise<ComplianceStatus[]> => {
    try {
      // Fetch real compliance data for multiple frameworks
      const frameworks = ['PCI-DSS', 'HIPAA', 'GDPR', 'NIST'];
      const results = await Promise.all(
        frameworks.map(async (fw) => {
          try {
            const res = await mlService.assessCompliance(fw);
            return {
              framework: fw,
              score: res.score,
              total_controls: 100, // Placeholder total
              passed_controls: res.compliant ? 100 : Math.round(res.score),
              failed_controls: res.compliant ? 0 : 100 - Math.round(res.score)
            };
          } catch (e) {
            return { framework: fw, score: 0, total_controls: 0, passed_controls: 0, failed_controls: 0 };
          }
        })
      );
      return results;
    } catch (error) {
      console.error('Error fetching compliance status:', error);
      return [];
    }
  },

  getTopVulnerabilities: async (limit: number = 5): Promise<TopVulnerability[]> => {
    // Mocking vulnerabilities
    return [];
  },

  getRecentAlerts: async (limit: number = 5): Promise<RecentAlert[]> => {
    try {
      const response = await api.get('/alerts?active_only=true');
      return response.data.slice(0, limit).map((a: any) => ({
        id: a.id,
        title: a.title,
        severity: a.severity,
        timestamp: a.timestamp,
        status: a.resolved ? 'resolved' : 'active'
      }));
    } catch (error) {
      console.error('Error fetching recent alerts:', error);
      return [];
    }
  },

  getAssetRiskDistribution: async (): Promise<any> => {
    return [];
  },

  getAttackSurfaceMetrics: async (): Promise<any> => {
    return {};
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