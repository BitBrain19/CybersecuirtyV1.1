/**
 * ML Service
 * =========
 * Client-side service for ML predictions API.
 *
 * Provides methods for:
 * - Threat detection predictions
 * - Vulnerability assessments
 * - ML service health checks
 * - Model information queries
 */

import { api } from "./api";

/**
 * Threat Detection Request
 */
export interface ThreatDetectionRequest {
  features: Record<string, any>;
  model_version?: string;
  request_id?: string;
}

/**
 * Threat Detection Response
 */
export interface ThreatDetectionResponse {
  request_id?: string;
  prediction: "benign" | "malicious" | "suspicious";
  confidence: number; // 0-1
  threat_score: number; // 0-10
  anomaly_score?: number; // 0-1
  processing_time_ms: number;
  model_version: string;
  timestamp: string;
  metadata: Record<string, any>;
}

/**
 * Vulnerability Assessment Request
 */
export interface VulnerabilityAssessmentRequest {
  features: Record<string, any>;
  model_version?: string;
  request_id?: string;
}

/**
 * Vulnerability Assessment Response
 */
export interface VulnerabilityAssessmentResponse {
  request_id?: string;
  vulnerability_score: number; // 0-10
  severity: "low" | "medium" | "high" | "critical";
  is_anomaly: boolean;
  cvss_base_score?: number;
  processing_time_ms: number;
  model_version: string;
  timestamp: string;
  metadata: Record<string, any>;
}

/**
 * ML Service Health Response
 */
export interface MLHealthResponse {
  status: "healthy" | "degraded" | "error";
  threat_model: "ready" | "error";
  vulnerability_model: "ready" | "error";
  timestamp: string;
  version: string;
  uptime_seconds?: number;
}

/**
 * Model Information
 */
export interface ModelInfo {
  name: string;
  version: string;
  status: string;
  last_updated: string;
}

/**
 * Models List Response
 */
export interface ModelsListResponse {
  models: ModelInfo[];
  timestamp: string;
}

/**
 * ML Service
 */
const mlService = {
  /**
   * Predict threat level for given features
   */
  predictThreat: async (
    request: ThreatDetectionRequest
  ): Promise<ThreatDetectionResponse> => {
    try {
      const response = await api.post<ThreatDetectionResponse>(
        "/ml/threat-detection",
        request
      );
      return response.data;
    } catch (error) {
      console.error("Error predicting threat:", error);
      throw error;
    }
  },

  /**
   * Assess vulnerability for given features
   */
  assessVulnerability: async (
    request: VulnerabilityAssessmentRequest
  ): Promise<VulnerabilityAssessmentResponse> => {
    try {
      const response = await api.post<VulnerabilityAssessmentResponse>(
        "/ml/vulnerability-assessment",
        request
      );
      return response.data;
    } catch (error) {
      console.error("Error assessing vulnerability:", error);
      throw error;
    }
  },

  /**
   * Batch threat predictions
   */
  predictThreats: async (
    requests: ThreatDetectionRequest[]
  ): Promise<ThreatDetectionResponse[]> => {
    try {
      const response = await api.post<ThreatDetectionResponse[]>(
        "/ml/threat-detection/batch",
        requests
      );
      return response.data;
    } catch (error) {
      console.error("Error in batch threat predictions:", error);
      throw error;
    }
  },

  /**
   * Batch vulnerability assessments
   */
  assessVulnerabilities: async (
    requests: VulnerabilityAssessmentRequest[]
  ): Promise<VulnerabilityAssessmentResponse[]> => {
    try {
      const response = await api.post<VulnerabilityAssessmentResponse[]>(
        "/ml/vulnerability-assessment/batch",
        requests
      );
      return response.data;
    } catch (error) {
      console.error("Error in batch vulnerability assessments:", error);
      throw error;
    }
  },

  /**
   * Check ML service health
   */
  checkHealth: async (): Promise<MLHealthResponse> => {
    try {
      const response = await api.get<MLHealthResponse>("/ml/health");
      return response.data;
    } catch (error) {
      console.error("Error checking ML service health:", error);
      throw error;
    }
  },

  /**
   * List available models
   */
  listModels: async (): Promise<ModelsListResponse> => {
    try {
      const response = await api.get<ModelsListResponse>("/ml/models");
      return response.data;
    } catch (error) {
      console.error("Error listing models:", error);
      throw error;
    }
  },

  /**
   * Helper: Create threat request for network features
   */
  createNetworkThreatRequest: (
    sourceIP: string,
    destinationPort: number,
    protocol: string,
    packetCount: number,
    byteCount: number,
    duration: number
  ): ThreatDetectionRequest => {
    return {
      features: {
        source_ip: sourceIP,
        destination_port: destinationPort,
        protocol,
        packet_count: packetCount,
        byte_count: byteCount,
        duration,
      },
    };
  },

  /**
   * Helper: Create vulnerability request
   */
  createVulnerabilityRequest: (
    age: number,
    version: string,
    patchLevel: number,
    complexityScore: number,
    osType: string,
    serviceType: string
  ): VulnerabilityAssessmentRequest => {
    return {
      features: {
        age,
        version,
        patch_level: patchLevel,
        complexity_score: complexityScore,
        os_type: osType,
        service_type: serviceType,
      },
    };
  },

  /**
   * Get Attack Paths Graph
   */
  getAttackPaths: async (): Promise<any> => {
    try {
      // Use the generic predict endpoint with model_name="attack_path"
      const response = await api.post("/ml/predict", {
        model_name: "attack_path",
        features: { operation: "get_graph" }
      });
      // The backend wraps the result in a PredictionOutput object
      return response.data.prediction;
    } catch (error) {
      console.error("Error fetching attack paths:", error);
      throw error;
    }
  },

  /**
   * Get SOAR Playbooks
   */
  getSOARPlaybooks: async (): Promise<any[]> => {
    try {
      const response = await api.post("/ml/predict", {
        model_name: "soar_engine",
        features: { operation: "list_playbooks" }
      });
      return response.data.prediction.playbooks || [];
    } catch (error) {
      console.error("Error fetching SOAR playbooks:", error);
      throw error;
    }
  },

  /**
   * Run SOAR Playbook
   */
  runSOARPlaybook: async (playbookId: string, incidentContext: any): Promise<any> => {
    try {
      const response = await api.post("/ml/predict", {
        model_name: "soar_engine",
        features: { 
          operation: "execute_playbook",
          playbook_id: playbookId,
          incident_context: incidentContext
        }
      });
      return response.data.prediction;
    } catch (error) {
      console.error("Error running SOAR playbook:", error);
      throw error;
    }
  },

  /**
   * Get UEBA Anomalies
   */
  getUEBAAnomalies: async (timeRange: string = "24h"): Promise<any[]> => {
    try {
      const response = await api.post("/ml/predict", {
        model_name: "ueba",
        features: { 
          operation: "get_anomalies",
          time_range: timeRange
        }
      });
      return response.data.prediction.anomalies || [];
    } catch (error) {
      console.error("Error fetching UEBA anomalies:", error);
      throw error;
    }
  },

  /**
   * Get EDR Endpoints
   */
  getEndpoints: async (): Promise<any[]> => {
    try {
      const response = await api.post("/ml/predict", {
        model_name: "edr_telemetry",
        features: { operation: "list_endpoints" }
      });
      return response.data.prediction.endpoints || [];
    } catch (error) {
      console.error("Error fetching endpoints:", error);
      throw error;
    }
  },

  /**
   * Assess Compliance
   */
  assessCompliance: async (framework: string = "NIST"): Promise<any> => {
    try {
      const response = await api.post("/ml/predict", {
        model_name: "compliance",
        features: { framework }
      });
      return response.data.prediction;
    } catch (error) {
      console.error("Error assessing compliance:", error);
      throw error;
    }
  },

  /**
   * Get EDR Alerts
   */
  getEDRAlerts: async (endpointId?: string): Promise<any[]> => {
    try {
      const response = await api.post("/ml/predict", {
        model_name: "edr_telemetry",
        features: { 
          operation: "list_alerts",
          endpoint_id: endpointId 
        }
      });
      return response.data.prediction.alerts || [];
    } catch (error) {
      console.error("Error fetching EDR alerts:", error);
      throw error;
    }
  }
};

export default mlService;
