import logging
import json
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
import time
import threading
import queue

from ..collectors.base_collector import BaseLogCollector
from ..parsers.base_parser import BaseLogParser
from ..parsers.parser_factory import ParserFactory

logger = logging.getLogger(__name__)

class LogPipeline:
    """
    Pipeline for processing logs from collectors, through parsers, and to output destinations.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the log pipeline.
        
        Args:
            config: Dictionary containing configuration parameters
                - batch_size: Maximum number of logs to process in a batch
                - processing_interval: Interval in seconds between processing batches
                - max_queue_size: Maximum size of the processing queue
                - num_worker_threads: Number of worker threads for processing
        """
        self.config = config
        self.batch_size = config.get('batch_size', 100)
        self.processing_interval = config.get('processing_interval', 5)
        self.max_queue_size = config.get('max_queue_size', 10000)
        self.num_worker_threads = config.get('num_worker_threads', 2)
        
        # Create the processing queue
        self.queue = queue.Queue(maxsize=self.max_queue_size)
        
        # Initialize collectors, parsers, and processors
        self.collectors = []
        self.parser = ParserFactory.create_default_parser(config.get('parser_config', {}))
        self.processors = []
        self.output_handlers = []
        
        # Control flags
        self.running = False
        self.worker_threads = []
        self._setup_logging()
    
    def _setup_logging(self):
        """
        Set up logging for the pipeline.
        """
        self.log_level = self.config.get('log_level', logging.INFO)
        logger.setLevel(self.log_level)
    
    def add_collector(self, collector: BaseLogCollector) -> None:
        """
        Add a log collector to the pipeline.
        
        Args:
            collector: The collector to add
        """
        self.collectors.append(collector)
        logger.info(f"Added collector: {collector.__class__.__name__}")
    
    def set_parser(self, parser: BaseLogParser) -> None:
        """
        Set the parser for the pipeline.
        
        Args:
            parser: The parser to use
        """
        self.parser = parser
        logger.info(f"Set parser: {parser.__class__.__name__}")
    
    def add_processor(self, processor: Callable[[Dict[str, Any]], Dict[str, Any]]) -> None:
        """
        Add a processor function to the pipeline.
        Processors transform log entries after parsing.
        
        Args:
            processor: Function that takes a log entry and returns a transformed log entry
        """
        self.processors.append(processor)
        logger.info(f"Added processor: {processor.__name__ if hasattr(processor, '__name__') else 'anonymous'}")
    
    def add_output_handler(self, handler: Callable[[List[Dict[str, Any]]], None]) -> None:
        """
        Add an output handler to the pipeline.
        Output handlers receive batches of processed logs.
        
        Args:
            handler: Function that takes a list of log entries and processes them
        """
        self.output_handlers.append(handler)
        logger.info(f"Added output handler: {handler.__name__ if hasattr(handler, '__name__') else 'anonymous'}")
    
    def start(self) -> None:
        """
        Start the log pipeline.
        """
        if self.running:
            logger.warning("Pipeline is already running")
            return
        
        self.running = True
        
        # Start collectors
        for collector in self.collectors:
            collector.start()
        
        # Start worker threads
        for i in range(self.num_worker_threads):
            thread = threading.Thread(target=self._worker_thread, name=f"LogPipelineWorker-{i}")
            thread.daemon = True
            thread.start()
            self.worker_threads.append(thread)
        
        # Start collection thread
        self.collection_thread = threading.Thread(target=self._collection_thread, name="LogPipelineCollector")
        self.collection_thread.daemon = True
        self.collection_thread.start()
        
        logger.info("Log pipeline started")
    
    def stop(self) -> None:
        """
        Stop the log pipeline.
        """
        if not self.running:
            logger.warning("Pipeline is not running")
            return
        
        self.running = False
        
        # Stop collectors
        for collector in self.collectors:
            collector.stop()
        
        # Wait for threads to finish
        if hasattr(self, 'collection_thread'):
            self.collection_thread.join(timeout=5)
        
        for thread in self.worker_threads:
            thread.join(timeout=5)
        
        self.worker_threads = []
        
        logger.info("Log pipeline stopped")
    
    def _collection_thread(self) -> None:
        """
        Thread that collects logs from collectors and adds them to the queue.
        """
        while self.running:
            try:
                start_time = time.time()
                
                # Collect logs from all collectors
                for collector in self.collectors:
                    if not collector.is_running():
                        continue
                    
                    try:
                        # Collect logs with metadata
                        collection_result = collector.collect_with_metadata()
                        logs = collection_result.get('logs', [])
                        metadata = collection_result.get('metadata', {})
                        
                        if logs:
                            logger.debug(f"Collected {len(logs)} logs from {collector.__class__.__name__}")
                            
                            # Add each log to the queue
                            for log in logs:
                                try:
                                    # Add collector metadata to each log
                                    log['collector_metadata'] = metadata
                                    
                                    # Add to queue, with timeout to avoid blocking forever
                                    self.queue.put(log, timeout=1)
                                except queue.Full:
                                    logger.warning("Processing queue is full, dropping log entry")
                                except Exception as e:
                                    logger.error(f"Error adding log to queue: {str(e)}")
                    
                    except Exception as e:
                        logger.error(f"Error collecting logs from {collector.__class__.__name__}: {str(e)}")
                
                # Sleep for the remaining time in the interval
                elapsed_time = time.time() - start_time
                sleep_time = max(0, self.processing_interval - elapsed_time)
                
                if sleep_time > 0:
                    time.sleep(sleep_time)
                    
            except Exception as e:
                logger.error(f"Error in collection thread: {str(e)}")
                time.sleep(1)  # Sleep to avoid tight loop in case of persistent errors
    
    def _worker_thread(self) -> None:
        """
        Worker thread that processes logs from the queue.
        """
        batch = []
        last_process_time = time.time()
        
        while self.running:
            try:
                # Process a batch when it reaches the batch size or the processing interval has elapsed
                current_time = time.time()
                process_batch = len(batch) >= self.batch_size or \
                               (len(batch) > 0 and current_time - last_process_time >= self.processing_interval)
                
                if process_batch:
                    self._process_batch(batch)
                    batch = []
                    last_process_time = current_time
                
                # Try to get a log entry from the queue
                try:
                    log_entry = self.queue.get(timeout=0.1)
                    batch.append(log_entry)
                    self.queue.task_done()
                except queue.Empty:
                    # If the queue is empty and we have logs in the batch, process them if enough time has passed
                    if len(batch) > 0 and current_time - last_process_time >= self.processing_interval:
                        self._process_batch(batch)
                        batch = []
                        last_process_time = current_time
                    
            except Exception as e:
                logger.error(f"Error in worker thread: {str(e)}")
                time.sleep(1)  # Sleep to avoid tight loop in case of persistent errors
        
        # Process any remaining logs in the batch when stopping
        if batch:
            self._process_batch(batch)
    
    def _process_batch(self, batch: List[Dict[str, Any]]) -> None:
        """
        Process a batch of log entries.
        
        Args:
            batch: List of log entries to process
        """
        if not batch:
            return
        
        try:
            # Parse the logs
            parsed_logs = self.parser.parse_batch(batch) if self.parser else batch
            
            # Apply processors
            processed_logs = parsed_logs
            for processor in self.processors:
                try:
                    processed_logs = [processor(log) for log in processed_logs]
                    # Filter out None results (processors can return None to drop a log)
                    processed_logs = [log for log in processed_logs if log is not None]
                except Exception as e:
                    logger.error(f"Error in processor: {str(e)}")
            
            # Send to output handlers
            if processed_logs:
                for handler in self.output_handlers:
                    try:
                        handler(processed_logs)
                    except Exception as e:
                        logger.error(f"Error in output handler: {str(e)}")
                
                logger.debug(f"Processed {len(processed_logs)} logs")
                
        except Exception as e:
            logger.error(f"Error processing batch: {str(e)}")