import logging
import time
import os
import sys
import platform
from typing import Dict, Any, List

from .collectors.collector_factory import CollectorFactory
from .parsers.parser_factory import ParserFactory
from .pipeline.log_pipeline import LogPipeline
from .pipeline.output_handlers import AIModelOutputHandler, FileOutputHandler
from .config import get_config

logger = logging.getLogger(__name__)

def setup_demo_pipeline() -> LogPipeline:
    """
    Set up a demonstration pipeline that collects logs and sends them to the AI model.
    
    Returns:
        Configured LogPipeline instance
    """
    # Get configuration
    config = get_config()
    pipeline_config = config.get_pipeline_config()
    
    # Create pipeline
    pipeline = LogPipeline(pipeline_config)
    
    # Detect OS and add appropriate collector
    os_type = platform.system().lower()
    collector = None
    
    if os_type == 'windows' and config.is_collector_enabled('windows'):
        collector = CollectorFactory.create_collector('windows', config.get_collector_config('windows'))
    elif os_type == 'linux' and config.is_collector_enabled('linux'):
        collector = CollectorFactory.create_collector('linux', config.get_collector_config('linux'))
    elif os_type == 'darwin' and config.is_collector_enabled('macos'):
        collector = CollectorFactory.create_collector('macos', config.get_collector_config('macos'))
    
    if collector:
        pipeline.add_collector(collector)
        logger.info(f"Added {collector.__class__.__name__} to the pipeline")
    else:
        logger.warning(f"No collector available for OS: {os_type}")
    
    # Add parser
    parser = ParserFactory.create_parser('unified', config.get_parser_config('unified'))
    pipeline.set_parser(parser)
    logger.info(f"Set parser to {parser.__class__.__name__}")
    
    # Add output handlers
    # 1. File output for debugging
    file_config = {
        'output_file': os.path.join('logs', 'collected_logs.json'),
        'append': True,
        'format': 'json'
    }
    pipeline.add_output_handler(FileOutputHandler(file_config))
    logger.info("Added FileOutputHandler to the pipeline")
    
    # 2. AI model output
    ai_model_config = {
        'model_endpoint': config.get('output', {}).get('handlers', [])[0].get('config', {}).get(
            'model_endpoint', 'http://ml-service:8000/api/v1/predict'
        ),
        'batch_size': 100,
        'timeout': 30,
        'include_metadata': True
    }
    pipeline.add_output_handler(AIModelOutputHandler(ai_model_config))
    logger.info("Added AIModelOutputHandler to the pipeline")
    
    return pipeline

def run_demo(duration_seconds: int = 300) -> None:
    """
    Run a demonstration of the log collection pipeline.
    
    Args:
        duration_seconds: How long to run the demonstration for (in seconds)
    """
    # Set up logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(os.path.join('logs', 'integration_demo.log'))
        ]
    )
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    logger.info("Starting log collection pipeline demonstration")
    
    # Set up the pipeline
    pipeline = setup_demo_pipeline()
    
    # Start the pipeline
    pipeline.start()
    logger.info("Pipeline started")
    
    try:
        # Run for the specified duration
        start_time = time.time()
        while time.time() - start_time < duration_seconds:
            # Print status every 30 seconds
            if int(time.time() - start_time) % 30 == 0:
                logger.info(f"Pipeline running for {int(time.time() - start_time)} seconds")
                logger.info(f"Logs processed: {pipeline.logs_processed}")
                logger.info(f"Errors: {pipeline.errors}")
            
            # Sleep to avoid high CPU usage
            time.sleep(1)
    
    except KeyboardInterrupt:
        logger.info("Demonstration interrupted by user")
    
    finally:
        # Stop the pipeline
        pipeline.stop()
        logger.info("Pipeline stopped")
        
        # Print summary
        logger.info("=== Demonstration Summary ===")
        logger.info(f"Total logs processed: {pipeline.logs_processed}")
        logger.info(f"Total errors: {pipeline.errors}")
        logger.info(f"Last collection time: {pipeline.last_collection_time}")

if __name__ == "__main__":
    # Get duration from command line argument, default to 5 minutes
    duration = 300
    if len(sys.argv) > 1:
        try:
            duration = int(sys.argv[1])
        except ValueError:
            logger.error(f"Invalid duration: {sys.argv[1]}. Using default of 300 seconds.")
    
    run_demo(duration)