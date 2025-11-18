from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query, Body
from typing import List, Dict, Any, Optional
import logging
import os
import platform
from datetime import datetime, timedelta

from ....log_collection.collectors.collector_factory import CollectorFactory
from ....log_collection.parsers.parser_factory import ParserFactory
from ....log_collection.pipeline.log_pipeline import LogPipeline
from ....log_collection.config import get_config
from ....core.security import get_current_active_user
from ....models.user import User

router = APIRouter()
logger = logging.getLogger(__name__)

# Initialize the log pipeline
config = get_config()
pipeline = LogPipeline(config.get_pipeline_config())

# Set up the pipeline with default collectors and parsers based on configuration
def setup_pipeline():
    # Add collectors based on the current OS and configuration
    os_type = platform.system().lower()
    
    if os_type == 'windows' and config.is_collector_enabled('windows'):
        collector = CollectorFactory.create_collector('windows', config.get_collector_config('windows'))
        pipeline.add_collector(collector)
        
    elif os_type == 'linux' and config.is_collector_enabled('linux'):
        collector = CollectorFactory.create_collector('linux', config.get_collector_config('linux'))
        pipeline.add_collector(collector)
        
    elif os_type == 'darwin' and config.is_collector_enabled('macos'):
        collector = CollectorFactory.create_collector('macos', config.get_collector_config('macos'))
        pipeline.add_collector(collector)
    
    # Set up the parser
    parser = ParserFactory.create_parser('unified', config.get_parser_config('unified'))
    pipeline.set_parser(parser)
    
    # Add output handlers
    for handler_config in config.get_output_handlers():
        handler_type = handler_config.get('type')
        handler_config = handler_config.get('config', {})
        
        if handler_type == 'file':
            from ....log_collection.pipeline.output_handlers import FileOutputHandler
            pipeline.add_output_handler(FileOutputHandler(handler_config))
            
        elif handler_type == 'http':
            from ....log_collection.pipeline.output_handlers import HttpOutputHandler
            pipeline.add_output_handler(HttpOutputHandler(handler_config))
            
        elif handler_type == 'redis':
            from ....log_collection.pipeline.output_handlers import RedisOutputHandler
            pipeline.add_output_handler(RedisOutputHandler(handler_config))
            
        elif handler_type == 'kafka':
            from ....log_collection.pipeline.output_handlers import KafkaOutputHandler
            pipeline.add_output_handler(KafkaOutputHandler(handler_config))
            
        elif handler_type == 'ai_model':
            from ....log_collection.pipeline.output_handlers import AIModelOutputHandler
            pipeline.add_output_handler(AIModelOutputHandler(handler_config))

# Set up the pipeline on module load
setup_pipeline()

@router.post("/collect", response_model=Dict[str, Any])
async def collect_logs(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_active_user)
):
    """
    Trigger log collection in the background.
    """
    # Start log collection in the background
    background_tasks.add_task(pipeline.collect_and_process)
    
    return {
        "status": "success",
        "message": "Log collection started in the background",
        "timestamp": datetime.now().isoformat()
    }

@router.get("/status", response_model=Dict[str, Any])
async def get_pipeline_status(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get the status of the log collection pipeline.
    """
    return {
        "status": "active" if pipeline.is_running() else "idle",
        "collectors": [collector.__class__.__name__ for collector in pipeline.collectors],
        "parser": pipeline.parser.__class__.__name__ if pipeline.parser else None,
        "output_handlers": [handler.__class__.__name__ for handler in pipeline.output_handlers],
        "last_collection": pipeline.last_collection_time.isoformat() if pipeline.last_collection_time else None,
        "logs_processed": pipeline.logs_processed,
        "errors": pipeline.errors
    }

@router.post("/configure", response_model=Dict[str, Any])
async def configure_pipeline(
    config_data: Dict[str, Any] = Body(...),
    current_user: User = Depends(get_current_active_user)
):
    """
    Update the configuration of the log collection pipeline.
    """
    try:
        # Update the configuration
        for section, section_data in config_data.items():
            if isinstance(section_data, dict):
                for key, value in section_data.items():
                    config.set(section, key, value)
            else:
                config.set(section, None, section_data)
        
        # Save the configuration
        config.save_config()
        
        # Reconfigure the pipeline
        pipeline.stop()
        setup_pipeline()
        
        return {
            "status": "success",
            "message": "Pipeline configuration updated",
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error configuring pipeline: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error configuring pipeline: {str(e)}")

@router.post("/ingest", response_model=Dict[str, Any])
async def ingest_logs(
    logs: List[Dict[str, Any]] = Body(...),
    background_tasks: BackgroundTasks = None,
    current_user: User = Depends(get_current_active_user)
):
    """
    Ingest logs directly into the pipeline.
    """
    try:
        # Process the logs
        if background_tasks:
            background_tasks.add_task(pipeline.process_logs, logs)
            processed = True
        else:
            processed = pipeline.process_logs(logs)
        
        return {
            "status": "success",
            "message": f"Ingested {len(logs)} logs",
            "processed": processed,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error ingesting logs: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Error ingesting logs: {str(e)}")

@router.get("/config", response_model=Dict[str, Any])
async def get_config_endpoint(
    current_user: User = Depends(get_current_active_user)
):
    """
    Get the current configuration of the log collection pipeline.
    """
    return config.config