import logging
import platform
from typing import Dict, Any, Optional

from .base_collector import BaseLogCollector

logger = logging.getLogger(__name__)

class CollectorFactory:
    """
    Factory class for creating log collectors based on the operating system.
    """
    
    @staticmethod
    def create_collector(collector_type: str, config: Dict[str, Any]) -> Optional[BaseLogCollector]:
        """
        Create a log collector instance based on the collector type.
        
        Args:
            collector_type: Type of collector to create ('windows', 'linux', 'macos', or 'auto')
            config: Configuration dictionary for the collector
            
        Returns:
            BaseLogCollector instance or None if creation fails
        """
        try:
            if collector_type == 'auto':
                # Automatically detect the operating system
                system = platform.system().lower()
                if 'windows' in system:
                    collector_type = 'windows'
                elif 'linux' in system:
                    collector_type = 'linux'
                elif 'darwin' in system:
                    collector_type = 'macos'
                else:
                    logger.error(f"Unsupported operating system for auto detection: {system}")
                    return None
            
            # Create the appropriate collector based on type
            if collector_type == 'windows':
                from .windows_collector import WindowsEventLogCollector
                return WindowsEventLogCollector(config)
            elif collector_type == 'linux':
                from .linux_collector import LinuxSyslogCollector
                return LinuxSyslogCollector(config)
            elif collector_type == 'macos':
                from .macos_collector import MacOSLogCollector
                return MacOSLogCollector(config)
            else:
                logger.error(f"Unknown collector type: {collector_type}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating collector of type {collector_type}: {str(e)}")
            return None
    
    @staticmethod
    def create_collector_for_current_os(config: Dict[str, Any]) -> Optional[BaseLogCollector]:
        """
        Create a log collector for the current operating system.
        
        Args:
            config: Configuration dictionary for the collector
            
        Returns:
            BaseLogCollector instance or None if creation fails
        """
        return CollectorFactory.create_collector('auto', config)