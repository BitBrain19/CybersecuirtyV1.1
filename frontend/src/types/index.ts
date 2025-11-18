export interface UserSettings {
  name?: string;
  email?: string;
  jobTitle?: string;
  company?: string;
  department?: string;
  notificationEmail?: string;
  notificationPreferences: NotificationPreferences;
  theme: ThemePreference;
  interfaceDensity?: string;
  animationsEnabled?: boolean;
  apiKey?: string;
  apiUsage?: {
    current: number;
    limit: number;
  };
  webhookUrl?: string;
}

export interface NotificationPreferences {
  securityAlerts?: boolean;
  vulnerabilityUpdates?: boolean;
  reportCompletion?: boolean;
  systemUpdates?: boolean;
}

export type ThemePreference = 'light' | 'dark' | 'system';

// Re-export report types
export * from './reports';
export * from './dashboard';
export * from './attackPaths';
export * from './alerts';