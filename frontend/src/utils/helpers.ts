import { format, parseISO, isValid } from 'date-fns';

/**
 * Format a date string or Date object to a human-readable format
 * @param date ISO date string or Date object
 * @param formatStr Optional format string (defaults to 'PPP')
 * @returns Formatted date string
 */
export const formatDate = (date: string | Date | undefined, formatStr: string = 'PPP'): string => {
  if (!date) return 'N/A';
  
  try {
    let dateObj: Date;
    
    if (typeof date === 'string') {
      dateObj = parseISO(date);
    } else {
      dateObj = date;
    }
    
    if (!isValid(dateObj)) {
      return typeof date === 'string' ? date : 'Invalid date';
    }
    
    return format(dateObj, formatStr);
  } catch (error) {
    console.error('Error formatting date:', error);
    return typeof date === 'string' ? date : 'Invalid date';
  }
};

/**
 * Get color class based on severity level
 * @param severity The severity level (low, medium, high, critical)
 * @returns CSS color class name
 */
export const getSeverityColor = (severity: string): string => {
  switch (severity?.toLowerCase()) {
    case 'low':
      return 'text-green-500';
    case 'medium':
      return 'text-yellow-500';
    case 'high':
      return 'text-orange-500';
    case 'critical':
      return 'text-red-500';
    default:
      return 'text-gray-500';
  }
};