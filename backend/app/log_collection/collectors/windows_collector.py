import logging
import win32evtlog
import win32con
import win32evtlogutil
import winerror
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from .base_collector import BaseLogCollector

logger = logging.getLogger(__name__)

class WindowsEventLogCollector(BaseLogCollector):
    """
    Collector for Windows Event Logs.
    Collects logs from Windows Event Log system.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Windows Event Log collector.
        
        Args:
            config: Dictionary containing configuration parameters
                - log_sources: List of event log sources to collect from (e.g., ['System', 'Application', 'Security'])
                - event_types: List of event types to collect (e.g., ['Error', 'Warning', 'Information'])
                - max_age_days: Maximum age of logs to collect in days
        """
        super().__init__(config)
        self.log_sources = config.get('log_sources', ['System', 'Application', 'Security'])
        self.event_types = config.get('event_types', ['Error', 'Warning', 'Information'])
        self.max_age_days = config.get('max_age_days', 1)  # Default: collect logs from the last day
        self.last_collected_record_numbers = {source: 0 for source in self.log_sources}
        
        # Map event types to Windows constants
        self.event_type_map = {
            'Error': win32con.EVENTLOG_ERROR_TYPE,
            'Warning': win32con.EVENTLOG_WARNING_TYPE,
            'Information': win32con.EVENTLOG_INFORMATION_TYPE,
            'AuditSuccess': win32con.EVENTLOG_AUDIT_SUCCESS,
            'AuditFailure': win32con.EVENTLOG_AUDIT_FAILURE
        }
        
        # Filter event types based on configuration
        self.event_type_filters = [self.event_type_map[et] for et in self.event_types if et in self.event_type_map]
        
    def collect(self) -> List[Dict[str, Any]]:
        """
        Collect Windows Event Logs from configured sources.
        
        Returns:
            List of log entries as dictionaries
        """
        all_logs = []
        
        for source in self.log_sources:
            try:
                logs = self._collect_from_source(source)
                all_logs.extend(logs)
                
                if logs:
                    logger.info(f"Collected {len(logs)} logs from Windows Event Log source: {source}")
                else:
                    logger.info(f"No new logs collected from Windows Event Log source: {source}")
                    
            except Exception as e:
                logger.error(f"Error collecting logs from Windows Event Log source {source}: {str(e)}")
        
        return all_logs
    
    def _collect_from_source(self, source: str) -> List[Dict[str, Any]]:
        """
        Collect logs from a specific Windows Event Log source.
        
        Args:
            source: The event log source name (e.g., 'System', 'Application')
            
        Returns:
            List of log entries as dictionaries
        """
        logs = []
        last_record_number = self.last_collected_record_numbers.get(source, 0)
        
        try:
            # Open the event log
            hand = win32evtlog.OpenEventLog(None, source)
            
            # Get total records count
            total_records = win32evtlog.GetNumberOfEventLogRecords(hand)
            oldest_record = win32evtlog.GetOldestEventLogRecord(hand)
            
            # Calculate the cutoff time for log age
            cutoff_time = datetime.now() - timedelta(days=self.max_age_days)
            
            # Read event logs
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            while events:
                for event in events:
                    # Skip if we've already processed this record
                    if event.RecordNumber <= last_record_number and last_record_number > 0:
                        continue
                    
                    # Update the last collected record number if this one is newer
                    if event.RecordNumber > self.last_collected_record_numbers.get(source, 0):
                        self.last_collected_record_numbers[source] = event.RecordNumber
                    
                    # Skip if event type doesn't match our filters
                    if self.event_type_filters and event.EventType not in self.event_type_filters:
                        continue
                    
                    # Convert event time to datetime
                    event_time = datetime.fromtimestamp(event.TimeGenerated)
                    
                    # Skip if event is older than our cutoff
                    if event_time < cutoff_time:
                        continue
                    
                    # Extract event data
                    event_data = self._parse_event(event, source)
                    logs.append(event_data)
                    
                    # Stop if we've reached the batch size limit
                    if len(logs) >= self.max_batch_size:
                        break
                
                # Stop if we've reached the batch size limit
                if len(logs) >= self.max_batch_size:
                    break
                    
                # Read more events
                events = win32evtlog.ReadEventLog(hand, flags, 0)
            
            # Close the event log
            win32evtlog.CloseEventLog(hand)
            
        except Exception as e:
            logger.error(f"Error reading from Windows Event Log source {source}: {str(e)}")
        
        return logs
    
    def _parse_event(self, event, source: str) -> Dict[str, Any]:
        """
        Parse a Windows Event Log event into a standardized dictionary.
        
        Args:
            event: The Windows Event Log event object
            source: The event log source name
            
        Returns:
            Dictionary containing parsed event data
        """
        event_type_name = 'Unknown'
        for name, value in self.event_type_map.items():
            if event.EventType == value:
                event_type_name = name
                break
        
        # Convert event time to ISO format
        event_time = datetime.fromtimestamp(event.TimeGenerated).isoformat()
        
        # Get event description
        try:
            message = win32evtlogutil.SafeFormatMessage(event, source)
        except Exception:
            message = "<Could not retrieve event message>"
        
        return {
            'timestamp': event_time,
            'source': source,
            'event_id': event.EventID,
            'event_type': event_type_name,
            'category': event.EventCategory,
            'record_number': event.RecordNumber,
            'computer_name': event.ComputerName,
            'user': event.StringInserts[1] if event.StringInserts and len(event.StringInserts) > 1 else None,
            'message': message,
            'raw_data': str(event.StringInserts) if event.StringInserts else None,
            'collector_type': 'windows_event_log'
        }
    
    def get_collector_info(self) -> Dict[str, str]:
        """
        Get information about this collector.
        
        Returns:
            Dictionary with collector metadata
        """
        return {
            'collector_name': 'Windows Event Log Collector',
            'os_type': 'Windows',
            'log_sources': ','.join(self.log_sources),
            'event_types': ','.join(self.event_types),
            'max_age_days': str(self.max_age_days)
        }