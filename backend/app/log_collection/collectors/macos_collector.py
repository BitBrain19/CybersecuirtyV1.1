import logging
import subprocess
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from .base_collector import BaseLogCollector

logger = logging.getLogger(__name__)

class MacOSLogCollector(BaseLogCollector):
    """
    Collector for macOS Unified Logging System.
    Collects logs from the macOS log command.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the macOS Log collector.
        
        Args:
            config: Dictionary containing configuration parameters
                - log_types: List of log types to collect (e.g., ['default', 'info', 'debug'])
                - subsystems: List of subsystems to collect from (e.g., ['com.apple.security'])
                - max_age_hours: Maximum age of logs to collect in hours
                - predicate: Custom predicate for log filtering
        """
        super().__init__(config)
        self.log_types = config.get('log_types', ['default', 'info', 'debug'])
        self.subsystems = config.get('subsystems', [])
        self.max_age_hours = config.get('max_age_hours', 24)  # Default: collect logs from the last 24 hours
        self.predicate = config.get('predicate', '')
        
        # Map for log types to their command-line arguments
        self.log_type_map = {
            'default': '--default',
            'info': '--info',
            'debug': '--debug',
            'activity': '--activity',
            'fault': '--fault',
            'error': '--error',
            'trace': '--trace'
        }
    
    def collect(self) -> List[Dict[str, Any]]:
        """
        Collect logs from macOS Unified Logging System.
        
        Returns:
            List of log entries as dictionaries
        """
        try:
            # Calculate the time range
            since_time = datetime.now() - timedelta(hours=self.max_age_hours)
            since_param = since_time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Build the log command
            cmd = ['log', 'show', '--style', 'json']
            
            # Add time range
            cmd.extend(['--start', since_param])
            
            # Add log types
            for log_type in self.log_types:
                if log_type in self.log_type_map:
                    cmd.append(self.log_type_map[log_type])
            
            # Add subsystems if specified
            if self.subsystems:
                subsystem_args = []
                for subsystem in self.subsystems:
                    subsystem_args.extend(['--predicate', f'subsystem == "{subsystem}"'])
                if subsystem_args:
                    cmd.extend(subsystem_args)
            
            # Add custom predicate if specified
            if self.predicate:
                cmd.extend(['--predicate', self.predicate])
            
            # Execute the command
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Process the output
            output, error = process.communicate()
            
            if process.returncode != 0:
                logger.error(f"macOS log command failed: {error}")
                return []
            
            # Parse the JSON output
            try:
                log_entries = json.loads(output)
                return self._parse_log_entries(log_entries)
            except json.JSONDecodeError as e:
                logger.error(f"Error parsing macOS log output as JSON: {str(e)}")
                return []
                
        except Exception as e:
            logger.error(f"Error collecting logs from macOS Unified Logging: {str(e)}")
            return []
    
    def _parse_log_entries(self, log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse macOS log entries into a standardized format.
        
        Args:
            log_entries: List of log entries from the macOS log command
            
        Returns:
            List of standardized log entries
        """
        parsed_logs = []
        
        for entry in log_entries:
            try:
                # Extract common fields
                timestamp = entry.get('timestamp')
                if timestamp:
                    # Convert to ISO format if needed
                    if not isinstance(timestamp, str):
                        timestamp = datetime.fromtimestamp(timestamp).isoformat()
                else:
                    timestamp = datetime.now().isoformat()
                
                # Map log level to severity
                log_type = entry.get('eventType', 'default')
                severity = self._map_log_type_to_severity(log_type)
                
                parsed_entry = {
                    'timestamp': timestamp,
                    'message': entry.get('eventMessage', ''),
                    'subsystem': entry.get('subsystem', ''),
                    'category': entry.get('category', ''),
                    'process': entry.get('processImagePath', ''),
                    'process_id': entry.get('processID', ''),
                    'thread_id': entry.get('threadID', ''),
                    'activity_id': entry.get('activityID', ''),
                    'trace_id': entry.get('traceID', ''),
                    'severity': severity,
                    'collector_type': 'macos_unified_logging'
                }
                
                parsed_logs.append(parsed_entry)
                
                # Stop if we've reached the batch size limit
                if len(parsed_logs) >= self.max_batch_size:
                    break
                    
            except Exception as e:
                logger.error(f"Error parsing macOS log entry: {str(e)}")
        
        return parsed_logs
    
    def _map_log_type_to_severity(self, log_type: str) -> str:
        """
        Map macOS log types to standard severity levels.
        
        Args:
            log_type: The macOS log type
            
        Returns:
            Standard severity level
        """
        severity_map = {
            'fault': 'crit',
            'error': 'err',
            'default': 'notice',
            'info': 'info',
            'debug': 'debug',
            'activity': 'info',
            'trace': 'debug'
        }
        
        return severity_map.get(log_type.lower(), 'info')
    
    def get_collector_info(self) -> Dict[str, str]:
        """
        Get information about this collector.
        
        Returns:
            Dictionary with collector metadata
        """
        return {
            'collector_name': 'macOS Unified Logging Collector',
            'os_type': 'macOS',
            'log_types': ','.join(self.log_types),
            'subsystems': ','.join(self.subsystems) if self.subsystems else 'All',
            'max_age_hours': str(self.max_age_hours)
        }