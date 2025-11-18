import { api } from './api';

export interface AttackPath {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  probability: number;
  impact: number;
  risk_score: number;
  status: 'active' | 'mitigated' | 'accepted';
  created_at: string;
  updated_at: string;
  discoveredAt?: string; // Added for AttackPaths.tsx
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  affected_assets: string[];
  mitre_techniques: string[];
  remediation_steps?: string[];
  nodeCount?: number;
  edgeCount?: number;
}

export interface AttackPathNode {
  id: string;
  label: string;
  type: 'entry_point' | 'vulnerability' | 'asset' | 'technique' | 'goal';
  description?: string;
  metadata?: Record<string, any>;
  position?: { x: number; y: number };
}

export interface AttackPathEdge {
  id: string;
  source: string;
  target: string;
  label?: string;
  probability?: number;
}

export interface AttackPathFilters {
  severity?: string[];
  status?: string[];
  mitreTechniques?: string[];
  affectedAssets?: string[];
  dateRange?: {
    start: string;
    end: string;
  };
  search?: string;
}

export interface AttackPathsResponse {
  attack_paths: AttackPath[];
  total: number;
  page: number;
  limit: number;
}

const attackPathService = {
  getAttackPaths: async (page = 1, limit = 10, filters?: AttackPathFilters): Promise<AttackPathsResponse> => {
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

        if (filters.mitreTechniques && filters.mitreTechniques.length > 0) {
          filters.mitreTechniques.forEach(technique => {
            params.append('mitre_technique', technique);
          });
        }

        if (filters.affectedAssets && filters.affectedAssets.length > 0) {
          filters.affectedAssets.forEach(asset => {
            params.append('affected_asset', asset);
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

      const response = await api.get(`/attack-paths`, { params });
      const data = response.data;
      if (Array.isArray(data)) {
        return {
          attack_paths: data,
          total: data.length,
          page,
          limit,
        };
      }
      return data;
    } catch (error) {
      console.error('Error fetching attack paths:', error);
      throw error;
    }
  },

  getAttackPathById: async (id: string): Promise<AttackPath> => {
    try {
      const response = await api.get(`/attack-paths/${id}`);
      return response.data;
    } catch (error) {
      console.error(`Error fetching attack path with ID ${id}:`, error);
      throw error;
    }
  },

  updateAttackPathStatus: async (id: string, status: 'active' | 'mitigated' | 'accepted', notes?: string): Promise<AttackPath> => {
    try {
      const response = await api.put(`/attack-paths/${id}/status`, { status, notes });
      return response.data;
    } catch (error) {
      console.error(`Error updating attack path status with ID ${id}:`, error);
      throw error;
    }
  },

  getAttackPathStatistics: async (timeframe: 'day' | 'week' | 'month' = 'week'): Promise<any> => {
    try {
      const response = await api.get(`/attack-paths/statistics`, {
        params: { timeframe },
      });
      return response.data;
    } catch (error) {
      console.error('Error fetching attack path statistics:', error);
      throw error;
    }
  },

  getMitreTechniques: async (): Promise<any[]> => {
    try {
      const response = await api.get(`/attack-paths/mitre-techniques`);
      return response.data;
    } catch (error) {
      console.error('Error fetching MITRE techniques:', error);
      throw error;
    }
  },

  simulateAttackPath: async (assetId: string, techniqueIds: string[]): Promise<AttackPath> => {
    try {
      const response = await api.post(`/attack-paths/simulate`, {
        asset_id: assetId,
        technique_ids: techniqueIds,
      });
      return response.data;
    } catch (error) {
      console.error('Error simulating attack path:', error);
      throw error;
    }
  },
};

// Add named export for fetchAttackPaths
export const fetchAttackPaths = async (): Promise<AttackPath[]> => {
  try {
    const response = await api.get(`/attack-paths`);
    return response.data;
  } catch (error) {
    console.error('Error fetching attack paths:', error);
    throw error;
  }
};

export default attackPathService;