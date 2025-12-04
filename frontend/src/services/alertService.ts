import { api } from './api';

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

const alertService = {
  getAlerts: async (page = 1, limit = 10, filters?: AlertFilters): Promise<AlertsResponse> => {
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        limit: limit.toString(),
      });

      // Add filters to params if they exist
      if (filters) {
        if (filters.severity && filters.severity.length > 0) {
          filters.severity.forEach(severity => {
            params.append('severity', severity);
          });
        }

        if (filters.status && filters.status.length > 0) {
          filters.status.forEach(status => {
            params.append('status', status);
          });
        }

        if (filters.source && filters.source.length > 0) {
          filters.source.forEach(source => {
            params.append('source', source);
          });
        }

        if (filters.dateRange) {
          params.append('start_date', filters.dateRange.start);
          params.append('end_date', filters.dateRange.end);
        }

        if (filters.search) {
          params.append('search', filters.search);
        }
      }

      const response = await api.get('/alerts/', { params });
      const data = response.data;

      // Normalize backend responses: support both array and object shapes
      if (Array.isArray(data)) {
        return {
          alerts: data as Alert[],
          total: data.length,
          page,
          limit,
        };
      }

      if (data && Array.isArray(data.alerts)) {
        return {
          alerts: data.alerts as Alert[],
          total: typeof data.total === 'number' ? data.total : (data.alerts as Alert[]).length,
          page: typeof data.page === 'number' ? data.page : page,
          limit: typeof data.limit === 'number' ? data.limit : limit,
        };
      }

      // Fallback to empty set on unexpected shape
      return {
        alerts: [],
        total: 0,
        page,
        limit,
      };
    } catch (error) {
      console.error('Error fetching alerts:', error);
      throw error;
    }
  },

  getAlertById: async (id: string): Promise<Alert> => {
    try {
      const response = await api.get(`/alerts/${id}`);
      return response.data;
    } catch (error) {
      console.error(`Error fetching alert with ID ${id}:`, error);
      throw error;
    }
  },

  acknowledgeAlert: async (id: string): Promise<Alert> => {
    try {
      // Backend doesn't have specific acknowledge endpoint, treating as resolve for now or just logging
      // For strict alignment, we'll use the resolve endpoint with a note
      const response = await api.post(`/alerts/${id}/resolve`, { notes: "Acknowledged via UI" });
      return response.data;
    } catch (error) {
      console.error(`Error acknowledging alert with ID ${id}:`, error);
      throw error;
    }
  },

  resolveAlert: async (id: string, notes?: string): Promise<Alert> => {
    try {
      // Backend uses POST for resolve
      const response = await api.post(`/alerts/${id}/resolve`, { notes });
      return response.data;
    } catch (error) {
      console.error(`Error resolving alert with ID ${id}:`, error);
      throw error;
    }
  },

  dismissAlert: async (id: string, reason?: string): Promise<Alert> => {
    try {
      // Backend doesn't have specific dismiss endpoint, treating as resolve
      const response = await api.post(`/alerts/${id}/resolve`, { notes: `Dismissed: ${reason}` });
      return response.data;
    } catch (error) {
      console.error(`Error dismissing alert with ID ${id}:`, error);
      throw error;
    }
  },

  getAlertSources: async (): Promise<string[]> => {
    try {
      const response = await api.get('/alerts/sources');
      return response.data;
    } catch (error) {
      console.error('Error fetching alert sources:', error);
      throw error;
    }
  },

  getAlertStatistics: async (timeframe: 'day' | 'week' | 'month' = 'week'): Promise<any> => {
    try {
      const response = await api.get('/alerts/statistics', {
        params: { timeframe },
      });
      return response.data;
    } catch (error) {
      console.error('Error fetching alert statistics:', error);
      throw error;
    }
  },
};

// Export individual functions for easier importing
export const fetchAlerts = alertService.getAlerts;
export const acknowledgeAlert = alertService.acknowledgeAlert;
export const dismissAlert = alertService.dismissAlert;
export const resolveAlert = alertService.resolveAlert;
export const getAlertById = alertService.getAlertById;
export const getAlertSources = alertService.getAlertSources;
export const getAlertStatistics = alertService.getAlertStatistics;

export default alertService;