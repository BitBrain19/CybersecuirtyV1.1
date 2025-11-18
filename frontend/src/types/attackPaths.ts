export enum AttackPathSeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export interface AttackPath {
  id: string;
  name: string;
  description: string;
  severity: AttackPathSeverity;
  affectedAssets: number;
  exploitability: number;
  remediationComplexity: string;
  createdAt: string;
  updatedAt: string;
  discoveredAt: string;
  status: string;
  nodeCount: number;
  edgeCount: number;
}