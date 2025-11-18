// API URL
export const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8001'

// WebSocket URL
export const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8001/ws'

// Refresh token interval (in milliseconds)
export const REFRESH_TOKEN_INTERVAL = 15 * 60 * 1000 // 15 minutes

// Pagination defaults
export const DEFAULT_PAGE_SIZE = 10
export const ITEMS_PER_PAGE = 10

// Chart colors
export const CHART_COLORS = {
  primary: '#0ea5e9',
  secondary: '#8b5cf6',
  danger: '#ef4444',
  warning: '#f59e0b',
  success: '#22c55e',
  info: '#3b82f6',
}

// Severity levels
export enum SeverityLevel {
  CRITICAL = 'critical',
  HIGH = 'high',
  MEDIUM = 'medium',
  LOW = 'low',
  INFO = 'info',
}

// Severity colors
export const SEVERITY_COLORS = {
  [SeverityLevel.CRITICAL]: '#ef4444', // Red
  [SeverityLevel.HIGH]: '#f97316', // Orange
  [SeverityLevel.MEDIUM]: '#f59e0b', // Amber
  [SeverityLevel.LOW]: '#22c55e', // Green
  [SeverityLevel.INFO]: '#3b82f6', // Blue
}

// User roles
export enum UserRole {
  ADMIN = 'admin',
  ANALYST = 'analyst',
  VIEWER = 'viewer',
}

// Role permissions
export const ROLE_PERMISSIONS = {
  [UserRole.ADMIN]: ['read', 'write', 'delete', 'manage_users', 'configure_system'],
  [UserRole.ANALYST]: ['read', 'write', 'remediate'],
  [UserRole.VIEWER]: ['read'],
}