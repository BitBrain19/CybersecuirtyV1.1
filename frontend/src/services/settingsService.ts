import { UserSettings } from '@/types';

// Mock data for development
const mockSettings: UserSettings = {
  name: 'John Doe',
  email: 'john.doe@example.com',
  jobTitle: 'Security Analyst',
  company: 'Acme Corp',
  department: 'Security Operations',
  notificationEmail: 'notifications@example.com',
  notificationPreferences: {
    securityAlerts: true,
    vulnerabilityUpdates: true,
    reportCompletion: false,
    systemUpdates: true,
  },
  theme: 'system',
  interfaceDensity: 'comfortable',
  animationsEnabled: true,
  apiKey: 'sk_test_12345abcdef',
  apiUsage: {
    current: 450,
    limit: 1000
  },
  webhookUrl: 'https://webhook.example.com/endpoint'
};

// In a real application, these functions would make API calls
export const fetchUserSettings = async (): Promise<UserSettings> => {
  // For development, return mock data
  // In production, this would be:
  // const response = await axios.get('/api/settings');
  // return response.data;
  
  return new Promise((resolve) => {
    setTimeout(() => resolve(mockSettings), 500);
  });
};

export const updateUserSettings = async (settings: UserSettings): Promise<UserSettings> => {
  // For development, just return the settings
  // In production, this would be:
  // const response = await axios.put('/api/settings', settings);
  // return response.data;
  
  return new Promise((resolve) => {
    setTimeout(() => resolve(settings), 500);
  });
};