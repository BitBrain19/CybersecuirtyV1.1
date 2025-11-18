import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from .base_parser import BaseLogParser

logger = logging.getLogger(__name__)

class UnifiedLogParser(BaseLogParser):
    """
    Parser that converts various log formats into a unified schema.
    This is the main parser that handles normalization of all log types.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the unified log parser.
        
        Args:
            config: Dictionary containing configuration parameters
                - include_raw_data: Whether to include the raw log data in the output
                - additional_fields: List of additional fields to extract from the raw data
        """
        super().__init__(config)
        self.include_raw_data = config.get('include_raw_data', False)
        self.additional_fields = config.get('additional_fields', [])
    
    def parse(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a log entry into the unified schema.
        
        Args:
            log_entry: The log entry to parse
            
        Returns:
            Parsed log entry in the unified schema
        """
        try:
            # Extract the collector type to determine the source format
            collector_type = log_entry.get('collector_type', 'unknown')
            
            # Create the base unified log structure
            unified_log = {
                'timestamp': self.normalize_timestamp(log_entry.get('timestamp', datetime.now().isoformat())),
                'source': self._extract_source(log_entry, collector_type),
                'severity': self.normalize_severity(log_entry.get('severity', 'info')),
                'message': log_entry.get('message', ''),
                'host': self._extract_host(log_entry, collector_type),
                'process': self._extract_process(log_entry, collector_type),
                'process_id': self._extract_process_id(log_entry, collector_type),
                'log_type': self._determine_log_type(log_entry, collector_type),
                'collector_type': collector_type,
                'metadata': self._extract_metadata(log_entry, collector_type)
            }
            
            # Add additional fields if specified
            for field in self.additional_fields:
                if field in log_entry and field not in unified_log:
                    unified_log[field] = log_entry[field]
            
            # Include raw data if configured
            if self.include_raw_data:
                unified_log['raw_data'] = log_entry
            
            return unified_log
            
        except Exception as e:
            logger.error(f"Error parsing log entry: {str(e)}")
            # Return a minimal valid log entry
            return {
                'timestamp': datetime.now().isoformat(),
                'source': 'parser_error',
                'severity': 'error',
                'message': f"Error parsing log: {str(e)}",
                'host': '',
                'process': '',
                'process_id': '',
                'log_type': 'error',
                'collector_type': 'parser_error',
                'metadata': {}
            }
    
    def _extract_source(self, log_entry: Dict[str, Any], collector_type: str) -> str:
        """
        Extract the source from a log entry based on collector type.
        
        Args:
            log_entry: The log entry
            collector_type: The collector type
            
        Returns:
            Source string
        """
        if collector_type == 'windows_event_log':
            return log_entry.get('source', '')
        elif collector_type == 'linux_syslog':
            return log_entry.get('facility', 'syslog')
        elif collector_type == 'linux_journald':
            return log_entry.get('unit', log_entry.get('facility', 'journald'))
        elif collector_type == 'macos_unified_logging':
            return log_entry.get('subsystem', 'unified_logging')
        else:
            return log_entry.get('source', 'unknown')
    
    def _extract_host(self, log_entry: Dict[str, Any], collector_type: str) -> str:
        """
        Extract the host from a log entry based on collector type.
        
        Args:
            log_entry: The log entry
            collector_type: The collector type
            
        Returns:
            Host string
        """
        if collector_type == 'windows_event_log':
            return log_entry.get('computer_name', '')
        elif collector_type in ('linux_syslog', 'linux_journald'):
            return log_entry.get('hostname', '')
        else:
            return log_entry.get('host', log_entry.get('hostname', ''))
    
    def _extract_process(self, log_entry: Dict[str, Any], collector_type: str) -> str:
        """
        Extract the process from a log entry based on collector type.
        
        Args:
            log_entry: The log entry
            collector_type: The collector type
            
        Returns:
            Process string
        """
        if collector_type == 'windows_event_log':
            # Windows event logs don't always have a clear process name
            return ''
        elif collector_type in ('linux_syslog', 'linux_journald'):
            return log_entry.get('program', '')
        elif collector_type == 'macos_unified_logging':
            return log_entry.get('process', '')
        else:
            return log_entry.get('process', '')
    
    def _extract_process_id(self, log_entry: Dict[str, Any], collector_type: str) -> str:
        """
        Extract the process ID from a log entry based on collector type.
        
        Args:
            log_entry: The log entry
            collector_type: The collector type
            
        Returns:
            Process ID string
        """
        if collector_type == 'windows_event_log':
            # Windows event logs don't always have a process ID
            return ''
        elif collector_type in ('linux_syslog', 'linux_journald'):
            return log_entry.get('pid', '')
        elif collector_type == 'macos_unified_logging':
            return log_entry.get('process_id', '')
        else:
            return log_entry.get('process_id', log_entry.get('pid', ''))
    
    def _determine_log_type(self, log_entry: Dict[str, Any], collector_type: str) -> str:
        """
        Determine the log type based on collector type and content.
        
        Args:
            log_entry: The log entry
            collector_type: The collector type
            
        Returns:
            Log type string
        """
        if collector_type == 'windows_event_log':
            return log_entry.get('event_type', 'windows_event')
        elif collector_type == 'linux_syslog':
            return 'syslog'
        elif collector_type == 'linux_journald':
            return 'journald'
        elif collector_type == 'macos_unified_logging':
            return log_entry.get('category', 'unified_log')
        else:
            return 'generic'
    
    def _extract_metadata(self, log_entry: Dict[str, Any], collector_type: str) -> Dict[str, Any]:
        """
        Extract metadata from a log entry based on collector type.
        
        Args:
            log_entry: The log entry
            collector_type: The collector type
            
        Returns:
            Metadata dictionary
        """
        metadata = {}
        
        # Common metadata fields to exclude from the metadata dictionary
        common_fields = {
            'timestamp', 'source', 'severity', 'message', 'host', 'hostname',
            'process', 'process_id', 'pid', 'collector_type', 'raw_data'
        }
        
        # Add collector-specific metadata
        if collector_type == 'windows_event_log':
            metadata.update({
                'event_id': log_entry.get('event_id', ''),
                'category': log_entry.get('category', ''),
                'record_number': log_entry.get('record_number', ''),
                'user': log_entry.get('user', '')
            })
        elif collector_type == 'linux_syslog':
            # No specific metadata for syslog
            pass
        elif collector_type == 'linux_journald':
            metadata.update({
                'unit': log_entry.get('unit', ''),
                'user': log_entry.get('user', '')
            })
        elif collector_type == 'macos_unified_logging':
            metadata.update({
                'category': log_entry.get('category', ''),
                'subsystem': log_entry.get('subsystem', ''),
                'activity_id': log_entry.get('activity_id', ''),
                'thread_id': log_entry.get('thread_id', ''),
                'trace_id': log_entry.get('trace_id', '')
            })
        
        # Add any remaining fields that aren't in common_fields
        for key, value in log_entry.items():
            if key not in common_fields and key not in metadata:
                metadata[key] = value
        
        return metadata