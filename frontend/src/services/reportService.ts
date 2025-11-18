import { api } from './api';
import { API_URL } from '@/utils/constants';

export interface Report {
  id: string;
  name: string;
  description: string;
  type: 'vulnerability' | 'compliance' | 'threat' | 'executive' | 'custom' | 'security_posture' | 'attack_surface' | 'incident';
  status: 'generating' | 'completed' | 'failed' | 'pending';
  created_at: string;
  completed_at?: string;
  created_by: string;
  file_url?: string;
  parameters?: Record<string, any>;
  progress?: number;
  error_message?: string;
  generatedAt?: string; // Added for Reports.tsx
}

export interface ReportFilters {
  type?: string[];
  status?: string[];
  dateRange?: {
    start: string;
    end: string;
  };
  search?: string;
}

export interface ReportsResponse {
  reports: Report[];
  total: number;
  page: number;
  limit: number;
}

export interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  type: 'vulnerability' | 'compliance' | 'threat' | 'executive' | 'custom';
  parameters_schema: Record<string, any>;
}

// Alias for compatibility with Reports.tsx
export const fetchReports = async (filters?: {
  status?: string;
  type?: string;
  search?: string;
  startDate?: string;
  endDate?: string;
}): Promise<Report[]> => {
  try {
    // Convert the filters to the format expected by the API
    const apiFilters: ReportFilters = {};
    
    if (filters) {
      if (filters.status) apiFilters.status = [filters.status];
      if (filters.type) apiFilters.type = [filters.type];
      if (filters.search) apiFilters.search = filters.search;
      if (filters.startDate && filters.endDate) {
        apiFilters.dateRange = {
          start: filters.startDate,
          end: filters.endDate
        };
      }
    }
    
    const response = await reportService.getReports(1, 100, apiFilters);
    return response.reports;
  } catch (error) {
    console.error('Error fetching reports:', error);
    throw error;
  }
};

export const generateReport = async (params: { type: string }): Promise<Report> => {
  try {
    const response = await api.post(`${API_URL}/reports/generate`, params);
    return response.data;
  } catch (error) {
    console.error('Error generating report:', error);
    throw error;
  }
};

const reportService = {
  getReports: async (page = 1, limit = 10, filters?: ReportFilters): Promise<ReportsResponse> => {
    try {
      const params = new URLSearchParams({
        page: page.toString(),
        limit: limit.toString(),
      });

      // Add filters to params if they exist
      if (filters) {
        if (filters.type && filters.type.length > 0) {
          filters.type.forEach(type => {
            params.append('type', type);
          });
        }

        if (filters.status && filters.status.length > 0) {
          filters.status.forEach(status => {
            params.append('status', status);
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

      const response = await api.get(`${API_URL}/reports`, { params });
      return response.data;
    } catch (error) {
      console.error('Error fetching reports:', error);
      throw error;
    }
  },

  getReportById: async (id: string): Promise<Report> => {
    try {
      const response = await api.get(`${API_URL}/reports/${id}`);
      return response.data;
    } catch (error) {
      console.error(`Error fetching report with ID ${id}:`, error);
      throw error;
    }
  },

  getReportTemplates: async (): Promise<ReportTemplate[]> => {
    try {
      const response = await api.get(`${API_URL}/reports/templates`);
      return response.data;
    } catch (error) {
      console.error('Error fetching report templates:', error);
      throw error;
    }
  },

  generateReport: async (templateId: string, name: string, description: string, parameters: Record<string, any>): Promise<Report> => {
    try {
      const response = await api.post(`${API_URL}/reports/generate`, {
        template_id: templateId,
        name,
        description,
        parameters,
      });
      return response.data;
    } catch (error) {
      console.error('Error generating report:', error);
      throw error;
    }
  },

  downloadReport: async (id: string): Promise<Blob> => {
    try {
      const response = await api.get(`${API_URL}/reports/${id}/download`, {
        responseType: 'blob',
      });
      return response.data;
    } catch (error) {
      console.error(`Error downloading report with ID ${id}:`, error);
      throw error;
    }
  },

  deleteReport: async (id: string): Promise<void> => {
    try {
      await api.delete(`${API_URL}/reports/${id}`);
    } catch (error) {
      console.error(`Error deleting report with ID ${id}:`, error);
      throw error;
    }
  },

  getReportStatus: async (id: string): Promise<Report> => {
    try {
      const response = await api.get(`${API_URL}/reports/${id}/status`);
      return response.data;
    } catch (error) {
      console.error(`Error fetching status for report with ID ${id}:`, error);
      throw error;
    }
  },

  scheduleReport: async (
    templateId: string,
    name: string,
    description: string,
    parameters: Record<string, any>,
    schedule: {
      frequency: 'daily' | 'weekly' | 'monthly';
      day?: number;
      time: string;
    }
  ): Promise<any> => {
    try {
      const response = await api.post(`${API_URL}/reports/schedule`, {
        template_id: templateId,
        name,
        description,
        parameters,
        schedule,
      });
      return response.data;
    } catch (error) {
      console.error('Error scheduling report:', error);
      throw error;
    }
  },
};

export default reportService;