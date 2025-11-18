import logging
import re
import os
import subprocess
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

from .base_collector import BaseLogCollector

logger = logging.getLogger(__name__)

class LinuxSyslogCollector(BaseLogCollector):
    """
    Collector for Linux Syslog.
    Collects logs from Linux syslog files and journald.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Linux Syslog collector.
        
        Args:
            config: Dictionary containing configuration parameters
                - log_files: List of log files to collect from (e.g., ['/var/log/syslog', '/var/log/auth.log'])
                - use_journald: Whether to collect from journald (systemd journal)
                - max_age_hours: Maximum age of logs to collect in hours
                - severity_levels: List of severity levels to collect (e.g., ['err', 'warning', 'info'])
        """
        super().__init__(config)
        self.log_files = config.get('log_files', ['/var/log/syslog', '/var/log/auth.log'])
        self.use_journald = config.get('use_journald', True)
        self.max_age_hours = config.get('max_age_hours', 24)  # Default: collect logs from the last 24 hours
        self.severity_levels = config.get('severity_levels', ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info'])
        
        # Track the last read position for each log file
        self.file_positions = {}
        
        # Regular expression for parsing syslog format
        self.syslog_pattern = re.compile(
            r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([\w\-\.]+)\s+([\w\/\.\-]+)(?:\[([0-9]+)\])?:\s+(.*)$'
        )
        
        # Map for severity levels
        self.severity_map = {
            'emerg': 0,   # System is unusable
            'alert': 1,   # Action must be taken immediately
            'crit': 2,    # Critical conditions
            'err': 3,     # Error conditions
            'error': 3,   # Alias for err
            'warning': 4, # Warning conditions
            'warn': 4,    # Alias for warning
            'notice': 5,  # Normal but significant condition
            'info': 6,    # Informational messages
            'debug': 7    # Debug-level messages
        }
    
    def collect(self) -> List[Dict[str, Any]]:
        """
        Collect logs from Linux syslog files and/or journald.
        
        Returns:
            List of log entries as dictionaries
        """
        all_logs = []
        
        # Collect from log files
        if self.log_files:
            file_logs = self._collect_from_files()
            all_logs.extend(file_logs)
            logger.info(f"Collected {len(file_logs)} logs from syslog files")
        
        # Collect from journald if enabled
        if self.use_journald:
            journald_logs = self._collect_from_journald()
            all_logs.extend(journald_logs)
            logger.info(f"Collected {len(journald_logs)} logs from journald")
        
        return all_logs
    
    def _collect_from_files(self) -> List[Dict[str, Any]]:
        """
        Collect logs from syslog files.
        
        Returns:
            List of log entries as dictionaries
        """
        logs = []
        cutoff_time = datetime.now() - timedelta(hours=self.max_age_hours)
        current_year = datetime.now().year
        
        for log_file in self.log_files:
            try:
                if not os.path.exists(log_file):
                    logger.warning(f"Log file does not exist: {log_file}")
                    continue
                
                # Get file size
                file_size = os.path.getsize(log_file)
                
                # If we've seen this file before, start from the last position
                # Otherwise, start from the beginning or calculate based on max age
                if log_file in self.file_positions:
                    start_pos = self.file_positions[log_file]
                    if start_pos > file_size:  # File was rotated
                        start_pos = 0
                else:
                    start_pos = 0
                
                with open(log_file, 'r') as f:
                    # Seek to the starting position
                    f.seek(start_pos)
                    
                    # Read and parse each line
                    for line in f:
                        # Parse the syslog line
                        log_entry = self._parse_syslog_line(line, current_year)
                        
                        if log_entry:
                            # Check if the log is within our time range
                            log_time = datetime.fromisoformat(log_entry['timestamp'])
                            if log_time >= cutoff_time:
                                logs.append(log_entry)
                            
                            # Stop if we've reached the batch size limit
                            if len(logs) >= self.max_batch_size:
                                break
                    
                    # Update the file position for next time
                    self.file_positions[log_file] = f.tell()
            
            except Exception as e:
                logger.error(f"Error reading log file {log_file}: {str(e)}")
            
            # Stop if we've reached the batch size limit
            if len(logs) >= self.max_batch_size:
                break
        
        return logs
    
    def _collect_from_journald(self) -> List[Dict[str, Any]]:
        """
        Collect logs from systemd journal (journald).
        
        Returns:
            List of log entries as dictionaries
        """
        logs = []
        
        try:
            # Calculate the time range for journalctl
            since_time = datetime.now() - timedelta(hours=self.max_age_hours)
            since_param = since_time.strftime("%Y-%m-%d %H:%M:%S")
            
            # Build the journalctl command
            cmd = [
                'journalctl',
                f'--since="{since_param}"',
                '--output=json',
                '--no-pager'
            ]
            
            # Add priority filter if severity levels are specified
            if self.severity_levels:
                priorities = [str(self.severity_map.get(level, 7)) for level in self.severity_levels if level in self.severity_map]
                if priorities:
                    priority_filter = ','.join(priorities)
                    cmd.append(f'--priority={priority_filter}')
            
            # Execute the command
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Process the output
            import json
            for line in process.stdout:
                try:
                    # Parse the JSON output
                    entry = json.loads(line)
                    
                    # Convert to our standard format
                    log_entry = self._parse_journald_entry(entry)
                    logs.append(log_entry)
                    
                    # Stop if we've reached the batch size limit
                    if len(logs) >= self.max_batch_size:
                        break
                        
                except json.JSONDecodeError:
                    continue
                except Exception as e:
                    logger.error(f"Error parsing journald entry: {str(e)}")
            
            # Wait for the process to complete
            process.wait()
            
            if process.returncode != 0:
                error = process.stderr.read()
                logger.error(f"journalctl command failed: {error}")
        
        except Exception as e:
            logger.error(f"Error collecting logs from journald: {str(e)}")
        
        return logs
    
    def _parse_syslog_line(self, line: str, current_year: int) -> Optional[Dict[str, Any]]:
        """
        Parse a syslog line into a standardized dictionary.
        
        Args:
            line: The syslog line to parse
            current_year: The current year (syslog doesn't include year)
            
        Returns:
            Dictionary containing parsed log data, or None if parsing failed
        """
        match = self.syslog_pattern.match(line.strip())
        if not match:
            return None
        
        timestamp_str, hostname, program, pid, message = match.groups()
        
        # Parse the timestamp (syslog doesn't include year)
        try:
            # Add the current year to the timestamp
            full_timestamp_str = f"{timestamp_str} {current_year}"
            timestamp = datetime.strptime(full_timestamp_str, "%b %d %H:%M:%S %Y")
            
            # If the parsed date is in the future, it's probably from the previous year
            if timestamp > datetime.now():
                timestamp = datetime.strptime(f"{timestamp_str} {current_year-1}", "%b %d %H:%M:%S %Y")
                
            timestamp_iso = timestamp.isoformat()
        except ValueError:
            # If we can't parse the timestamp, use current time
            timestamp_iso = datetime.now().isoformat()
        
        # Determine severity level from message content (heuristic)
        severity = 'info'  # Default
        lower_message = message.lower()
        if any(term in lower_message for term in ['emergency', 'emerg', 'panic']):
            severity = 'emerg'
        elif any(term in lower_message for term in ['alert']):
            severity = 'alert'
        elif any(term in lower_message for term in ['critical', 'crit', 'fatal']):
            severity = 'crit'
        elif any(term in lower_message for term in ['error', 'err', 'failure', 'failed']):
            severity = 'err'
        elif any(term in lower_message for term in ['warning', 'warn']):
            severity = 'warning'
        elif any(term in lower_message for term in ['notice', 'notification']):
            severity = 'notice'
        elif any(term in lower_message for term in ['info', 'information']):
            severity = 'info'
        elif any(term in lower_message for term in ['debug']):
            severity = 'debug'
        
        return {
            'timestamp': timestamp_iso,
            'hostname': hostname,
            'program': program,
            'pid': pid,
            'message': message,
            'severity': severity,
            'facility': 'syslog',  # Default facility
            'collector_type': 'linux_syslog'
        }
    
    def _parse_journald_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        """
        Parse a journald entry into a standardized dictionary.
        
        Args:
            entry: The journald entry as a dictionary
            
        Returns:
            Dictionary containing parsed log data
        """
        # Extract common fields
        timestamp = entry.get('__REALTIME_TIMESTAMP', '')
        if timestamp:
            # Convert microseconds since epoch to ISO format
            timestamp_dt = datetime.fromtimestamp(int(timestamp) / 1000000)
            timestamp_iso = timestamp_dt.isoformat()
        else:
            timestamp_iso = datetime.now().isoformat()
        
        # Map priority to severity
        priority = entry.get('PRIORITY')
        severity = 'info'  # Default
        if priority is not None:
            for name, value in self.severity_map.items():
                if str(value) == str(priority):
                    severity = name
                    break
        
        return {
            'timestamp': timestamp_iso,
            'hostname': entry.get('_HOSTNAME', ''),
            'program': entry.get('SYSLOG_IDENTIFIER', entry.get('_COMM', '')),
            'pid': entry.get('_PID', ''),
            'message': entry.get('MESSAGE', ''),
            'severity': severity,
            'facility': entry.get('SYSLOG_FACILITY', ''),
            'unit': entry.get('_SYSTEMD_UNIT', ''),
            'user': entry.get('_UID', ''),
            'collector_type': 'linux_journald'
        }
    
    def get_collector_info(self) -> Dict[str, str]:
        """
        Get information about this collector.
        
        Returns:
            Dictionary with collector metadata
        """
        return {
            'collector_name': 'Linux Syslog Collector',
            'os_type': 'Linux',
            'log_files': ','.join(self.log_files),
            'use_journald': str(self.use_journald),
            'max_age_hours': str(self.max_age_hours),
            'severity_levels': ','.join(self.severity_levels)
        }