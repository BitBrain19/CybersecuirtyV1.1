from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import logging
import time
from datetime import datetime

logger = logging.getLogger(__name__)

class BaseLogCollector(ABC):
    """
    Abstract base class for all log collectors.
    Provides common functionality and defines the interface that all collectors must implement.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the log collector with configuration.
        
        Args:
            config: Dictionary containing configuration parameters
        """
        self.config = config
        self.running = False
        self.collection_interval = config.get('collection_interval', 60)  # Default: collect every 60 seconds
        self.max_batch_size = config.get('max_batch_size', 1000)  # Default: max 1000 logs per batch
        self.last_collection_time = None
        self._setup_logging()
        
    def _setup_logging(self):
        """
        Set up logging for this collector.
        """
        self.log_level = self.config.get('log_level', logging.INFO)
        logger.setLevel(self.log_level)
    
    @abstractmethod
    def collect(self) -> List[Dict[str, Any]]:
        """
        Collect logs from the source.
        Must be implemented by subclasses.
        
        Returns:
            List of log entries as dictionaries
        """
        pass
    
    @abstractmethod
    def get_collector_info(self) -> Dict[str, str]:
        """
        Get information about this collector.
        Must be implemented by subclasses.
        
        Returns:
            Dictionary with collector metadata
        """
        pass
    
    def start(self):
        """
        Start the log collection process.
        """
        self.running = True
        logger.info(f"Started log collector: {self.__class__.__name__}")
        
    def stop(self):
        """
        Stop the log collection process.
        """
        self.running = False
        logger.info(f"Stopped log collector: {self.__class__.__name__}")
    
    def is_running(self) -> bool:
        """
        Check if the collector is running.
        
        Returns:
            True if running, False otherwise
        """
        return self.running
    
    def collect_with_metadata(self) -> Dict[str, Any]:
        """
        Collect logs and add metadata.
        
        Returns:
            Dictionary with logs and metadata
        """
        try:
            start_time = time.time()
            logs = self.collect()
            end_time = time.time()
            
            collection_time = end_time - start_time
            self.last_collection_time = datetime.now()
            
            metadata = {
                'collector_type': self.__class__.__name__,
                'collection_timestamp': self.last_collection_time.isoformat(),
                'collection_duration_seconds': collection_time,
                'log_count': len(logs),
                **self.get_collector_info()
            }
            
            return {
                'metadata': metadata,
                'logs': logs
            }
        except Exception as e:
            logger.error(f"Error collecting logs: {str(e)}")
            return {
                'metadata': {
                    'collector_type': self.__class__.__name__,
                    'collection_timestamp': datetime.now().isoformat(),
                    'error': str(e),
                    **self.get_collector_info()
                },
                'logs': []
            }