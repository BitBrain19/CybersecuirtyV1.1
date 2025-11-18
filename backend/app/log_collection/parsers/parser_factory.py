import logging
from typing import Dict, Any, Optional

from .base_parser import BaseLogParser
from .unified_parser import UnifiedLogParser

logger = logging.getLogger(__name__)

class ParserFactory:
    """
    Factory class for creating log parsers.
    """
    
    @staticmethod
    def create_parser(parser_type: str, config: Dict[str, Any]) -> Optional[BaseLogParser]:
        """
        Create a log parser instance based on the parser type.
        
        Args:
            parser_type: Type of parser to create ('unified' or other custom parsers)
            config: Configuration dictionary for the parser
            
        Returns:
            BaseLogParser instance or None if creation fails
        """
        try:
            if parser_type == 'unified':
                return UnifiedLogParser(config)
            else:
                logger.error(f"Unknown parser type: {parser_type}")
                return None
                
        except Exception as e:
            logger.error(f"Error creating parser of type {parser_type}: {str(e)}")
            return None
    
    @staticmethod
    def create_default_parser(config: Dict[str, Any] = None) -> BaseLogParser:
        """
        Create the default unified parser.
        
        Args:
            config: Configuration dictionary for the parser (optional)
            
        Returns:
            UnifiedLogParser instance
        """
        if config is None:
            config = {}
        
        return UnifiedLogParser(config)