export interface Report {
  id: string;
  title: string;
  name?: string; // Added for Reports.tsx
  description: string;
  createdAt: string;
  updatedAt: string;
  generatedAt?: string; // Added for Reports.tsx
  status: ReportStatus; // Updated to use enum only
  type: ReportType;
  severity?: 'low' | 'medium' | 'high' | 'critical';
  assignedTo?: string;
}

export enum ReportStatus {
  Draft = 'draft',
  InProgress = 'in-progress',
  Completed = 'completed',
  Archived = 'archived',
  Failed = 'failed',
  Generating = 'generating',
  Pending = 'pending'
}

export enum ReportType {
  Vulnerability = 'vulnerability',
  Compliance = 'compliance',
  Security = 'security',
  Performance = 'performance',
  Custom = 'custom',
  SecurityPosture = 'security_posture',
  AttackSurface = 'attack_surface',
  Incident = 'incident'
}