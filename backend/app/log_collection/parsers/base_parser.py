from abc import ABC, abstractmethod
from typing import Dict, Any, List, Optional
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class BaseLogParser(ABC):
    """
    Abstract base class for all log parsers.
    Provides common functionality and defines the interface that all parsers must implement.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the log parser with configuration.
        
        Args:
            config: Dictionary containing configuration parameters
        """
        self.config = config
        self._setup_logging()
    
    def _setup_logging(self):
        """
        Set up logging for this parser.
        """
        self.log_level = self.config.get('log_level', logging.INFO)
        logger.setLevel(self.log_level)
    
    @abstractmethod
    def parse(self, log_entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a log entry into the unified schema.
        Must be implemented by subclasses.
        
        Args:
            log_entry: The log entry to parse
            
        Returns:
            Parsed log entry in the unified schema
        """
        pass
    
    def parse_batch(self, log_entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Parse a batch of log entries.
        
        Args:
            log_entries: List of log entries to parse
            
        Returns:
            List of parsed log entries in the unified schema
        """
        parsed_entries = []
        
        for entry in log_entries:
            try:
                parsed_entry = self.parse(entry)
                if parsed_entry:
                    parsed_entries.append(parsed_entry)
            except Exception as e:
                logger.error(f"Error parsing log entry: {str(e)}")
        
        return parsed_entries
    
    def normalize_timestamp(self, timestamp: Any) -> str:
        """
        Normalize a timestamp to ISO format.
        
        Args:
            timestamp: The timestamp to normalize (string, datetime, or timestamp)
            
        Returns:
            ISO formatted timestamp string
        """
        if isinstance(timestamp, datetime):
            return timestamp.isoformat()
        elif isinstance(timestamp, (int, float)):
            return datetime.fromtimestamp(timestamp).isoformat()
        elif isinstance(timestamp, str):
            # Try to parse common timestamp formats
            for fmt in [
                "%Y-%m-%dT%H:%M:%S.%f",  # ISO format with microseconds
                "%Y-%m-%dT%H:%M:%S",     # ISO format without microseconds
                "%Y-%m-%d %H:%M:%S",     # Common datetime format
                "%b %d %H:%M:%S %Y",    # Syslog format with year
                "%b %d %H:%M:%S"         # Syslog format without year
            ]:
                try:
                    dt = datetime.strptime(timestamp, fmt)
                    # If the format doesn't include year, add current year
                    if fmt == "%b %d %H:%M:%S":
                        current_year = datetime.now().year
                        dt = dt.replace(year=current_year)
                    return dt.isoformat()
                except ValueError:
                    continue
        
        # If all parsing attempts fail, return the current time
        logger.warning(f"Could not parse timestamp: {timestamp}, using current time instead")
        return datetime.now().isoformat()
    
    def normalize_severity(self, severity: str) -> str:
        """
        Normalize severity levels to a standard set.
        
        Args:
            severity: The severity level to normalize
            
        Returns:
            Normalized severity level
        """
        severity_map = {
            # Critical levels
            'critical': 'critical',
            'crit': 'critical',
            'fatal': 'critical',
            'emerg': 'critical',
            'emergency': 'critical',
            'panic': 'critical',
            'alert': 'critical',
            
            # Error levels
            'error': 'error',
            'err': 'error',
            'severe': 'error',
            'failure': 'error',
            'failed': 'error',
            
            # Warning levels
            'warning': 'warning',
            'warn': 'warning',
            
            # Info levels
            'info': 'info',
            'information': 'info',
            'notice': 'info',
            'notification': 'info',
            'note': 'info',
            
            # Debug levels
            'debug': 'debug',
            'trace': 'debug',
            'verbose': 'debug'
        }
        
        if not severity:
            return 'info'  # Default
        
        normalized = severity_map.get(severity.lower(), 'info')
        return normalized