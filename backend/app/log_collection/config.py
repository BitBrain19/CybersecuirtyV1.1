import os
import json
import logging
from typing import Dict, Any, List, Optional, Union
from pathlib import Path

logger = logging.getLogger(__name__)

class LogCollectionConfig:
    """
    Configuration manager for the log collection system.
    Handles loading, validating, and providing access to configuration settings.
    """
    
    DEFAULT_CONFIG = {
        "collectors": {
            "windows": {
                "enabled": True,
                "event_sources": ["System", "Application", "Security"],
                "event_types": ["Error", "Warning", "Information"],
                "max_age_days": 7
            },
            "linux": {
                "enabled": True,
                "log_files": ["/var/log/syslog", "/var/log/auth.log"],
                "use_journald": True,
                "severity_levels": ["emerg", "alert", "crit", "err", "warning"],
                "max_age_days": 7
            },
            "macos": {
                "enabled": True,
                "log_types": ["system", "security", "user"],
                "subsystems": [],  # Empty means all subsystems
                "max_age_days": 7
            }
        },
        "parsers": {
            "unified": {
                "normalize_timestamps": True,
                "normalize_severity": True,
                "include_raw_data": False
            }
        },
        "pipeline": {
            "batch_size": 100,
            "max_queue_size": 10000,
            "processing_threads": 2,
            "collection_interval_seconds": 60
        },
        "output": {
            "handlers": [
                {
                    "type": "ai_model",
                    "enabled": True,
                    "config": {
                        "model_endpoint": "http://ml-service:8000/api/v1/predict",
                        "batch_size": 100,
                        "timeout": 30,
                        "include_metadata": True
                    }
                },
                {
                    "type": "file",
                    "enabled": True,
                    "config": {
                        "output_file": "logs/unified_logs.json",
                        "append": True,
                        "format": "json"
                    }
                }
            ]
        },
        "logging": {
            "level": "INFO",
            "file": "logs/log_collection.log",
            "max_size_mb": 10,
            "backup_count": 5
        }
    }
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize the configuration manager.
        
        Args:
            config_path: Path to the configuration file. If None, uses default config.
        """
        self.config_path = config_path
        self.config = self.DEFAULT_CONFIG.copy()
        
        if config_path:
            self.load_config(config_path)
        
        # Set up logging based on the configuration
        self._setup_logging()
    
    def _setup_logging(self):
        """
        Set up logging based on the configuration.
        """
        log_config = self.config.get("logging", {})
        log_level = getattr(logging, log_config.get("level", "INFO"))
        log_file = log_config.get("file", "logs/log_collection.log")
        
        # Create the log directory if it doesn't exist
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)
        
        # Configure the root logger
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
    
    def load_config(self, config_path: str) -> None:
        """
        Load configuration from a file.
        
        Args:
            config_path: Path to the configuration file.
        """
        try:
            with open(config_path, 'r') as f:
                user_config = json.load(f)
            
            # Merge the user configuration with the default configuration
            self._merge_configs(self.config, user_config)
            logger.info(f"Loaded configuration from {config_path}")
            
        except FileNotFoundError:
            logger.warning(f"Configuration file not found: {config_path}. Using default configuration.")
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing configuration file: {str(e)}. Using default configuration.")
        except Exception as e:
            logger.error(f"Unexpected error loading configuration: {str(e)}. Using default configuration.")
    
    def _merge_configs(self, base_config: Dict[str, Any], override_config: Dict[str, Any]) -> None:
        """
        Recursively merge override_config into base_config.
        
        Args:
            base_config: Base configuration to merge into.
            override_config: Configuration to merge from.
        """
        for key, value in override_config.items():
            if key in base_config and isinstance(base_config[key], dict) and isinstance(value, dict):
                self._merge_configs(base_config[key], value)
            else:
                base_config[key] = value
    
    def save_config(self, config_path: Optional[str] = None) -> None:
        """
        Save the current configuration to a file.
        
        Args:
            config_path: Path to save the configuration file. If None, uses the path from initialization.
        """
        save_path = config_path or self.config_path
        if not save_path:
            logger.warning("No configuration path specified. Cannot save configuration.")
            return
        
        try:
            # Create the directory if it doesn't exist
            os.makedirs(os.path.dirname(os.path.abspath(save_path)), exist_ok=True)
            
            with open(save_path, 'w') as f:
                json.dump(self.config, f, indent=2)
            
            logger.info(f"Saved configuration to {save_path}")
            
        except Exception as e:
            logger.error(f"Error saving configuration: {str(e)}")
    
    def get(self, section: str, key: Optional[str] = None, default: Any = None) -> Any:
        """
        Get a configuration value.
        
        Args:
            section: Configuration section.
            key: Configuration key within the section. If None, returns the entire section.
            default: Default value to return if the key is not found.
            
        Returns:
            The configuration value, or the default if not found.
        """
        if section not in self.config:
            return default
        
        if key is None:
            return self.config[section]
        
        return self.config[section].get(key, default)
    
    def set(self, section: str, key: str, value: Any) -> None:
        """
        Set a configuration value.
        
        Args:
            section: Configuration section.
            key: Configuration key within the section.
            value: Value to set.
        """
        if section not in self.config:
            self.config[section] = {}
        
        self.config[section][key] = value
    
    def get_collector_config(self, collector_type: str) -> Dict[str, Any]:
        """
        Get the configuration for a specific collector type.
        
        Args:
            collector_type: Type of collector (windows, linux, macos).
            
        Returns:
            Configuration dictionary for the collector.
        """
        collectors_config = self.config.get("collectors", {})
        return collectors_config.get(collector_type, {})
    
    def get_parser_config(self, parser_type: str) -> Dict[str, Any]:
        """
        Get the configuration for a specific parser type.
        
        Args:
            parser_type: Type of parser (unified, etc.).
            
        Returns:
            Configuration dictionary for the parser.
        """
        parsers_config = self.config.get("parsers", {})
        return parsers_config.get(parser_type, {})
    
    def get_pipeline_config(self) -> Dict[str, Any]:
        """
        Get the configuration for the pipeline.
        
        Returns:
            Configuration dictionary for the pipeline.
        """
        return self.config.get("pipeline", {})
    
    def get_output_handlers(self) -> List[Dict[str, Any]]:
        """
        Get the configuration for all enabled output handlers.
        
        Returns:
            List of output handler configurations.
        """
        output_config = self.config.get("output", {})
        handlers = output_config.get("handlers", [])
        
        # Filter to only enabled handlers
        return [h for h in handlers if h.get("enabled", True)]
    
    def is_collector_enabled(self, collector_type: str) -> bool:
        """
        Check if a collector is enabled.
        
        Args:
            collector_type: Type of collector (windows, linux, macos).
            
        Returns:
            True if the collector is enabled, False otherwise.
        """
        collector_config = self.get_collector_config(collector_type)
        return collector_config.get("enabled", False)


# Create a singleton instance of the configuration
config_instance = None

def get_config(config_path: Optional[str] = None) -> LogCollectionConfig:
    """
    Get the singleton configuration instance.
    
    Args:
        config_path: Path to the configuration file. Only used if the instance doesn't exist yet.
        
    Returns:
        The configuration instance.
    """
    global config_instance
    if config_instance is None:
        config_instance = LogCollectionConfig(config_path)
    return config_instance