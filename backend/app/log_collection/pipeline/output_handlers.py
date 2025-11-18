import logging
import json
import requests
from typing import Dict, List, Any, Optional
from datetime import datetime
import time
import os
import redis
from kafka import KafkaProducer

logger = logging.getLogger(__name__)

class BaseOutputHandler:
    """
    Base class for output handlers that process batches of logs.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the output handler.
        
        Args:
            config: Dictionary containing configuration parameters
        """
        self.config = config
        self._setup_logging()
    
    def _setup_logging(self):
        """
        Set up logging for this handler.
        """
        self.log_level = self.config.get('log_level', logging.INFO)
        logger.setLevel(self.log_level)
    
    def handle(self, logs: List[Dict[str, Any]]) -> None:
        """
        Handle a batch of logs.
        Must be implemented by subclasses.
        
        Args:
            logs: List of log entries to handle
        """
        raise NotImplementedError("Subclasses must implement handle()")
    
    def __call__(self, logs: List[Dict[str, Any]]) -> None:
        """
        Make the handler callable.
        
        Args:
            logs: List of log entries to handle
        """
        self.handle(logs)


class FileOutputHandler(BaseOutputHandler):
    """
    Output handler that writes logs to a file.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the file output handler.
        
        Args:
            config: Dictionary containing configuration parameters
                - output_file: Path to the output file
                - append: Whether to append to the file or overwrite it
                - format: Output format ('json' or 'text')
        """
        super().__init__(config)
        self.output_file = config.get('output_file', 'logs.json')
        self.append = config.get('append', True)
        self.format = config.get('format', 'json')
        
        # Create the output directory if it doesn't exist
        os.makedirs(os.path.dirname(os.path.abspath(self.output_file)), exist_ok=True)
    
    def handle(self, logs: List[Dict[str, Any]]) -> None:
        """
        Write logs to a file.
        
        Args:
            logs: List of log entries to write
        """
        try:
            mode = 'a' if self.append else 'w'
            with open(self.output_file, mode, encoding='utf-8') as f:
                if self.format == 'json':
                    for log in logs:
                        f.write(json.dumps(log) + '\n')
                else:  # text format
                    for log in logs:
                        timestamp = log.get('timestamp', datetime.now().isoformat())
                        severity = log.get('severity', 'info')
                        source = log.get('source', 'unknown')
                        message = log.get('message', '')
                        f.write(f"[{timestamp}] [{severity.upper()}] [{source}] {message}\n")
            
            logger.debug(f"Wrote {len(logs)} logs to {self.output_file}")
            
        except Exception as e:
            logger.error(f"Error writing logs to file: {str(e)}")


class HttpOutputHandler(BaseOutputHandler):
    """
    Output handler that sends logs to an HTTP endpoint.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the HTTP output handler.
        
        Args:
            config: Dictionary containing configuration parameters
                - endpoint_url: URL of the HTTP endpoint
                - method: HTTP method to use ('POST' or 'PUT')
                - headers: Dictionary of HTTP headers
                - timeout: Request timeout in seconds
                - max_retries: Maximum number of retries for failed requests
                - retry_delay: Delay between retries in seconds
        """
        super().__init__(config)
        self.endpoint_url = config.get('endpoint_url', '')
        self.method = config.get('method', 'POST')
        self.headers = config.get('headers', {'Content-Type': 'application/json'})
        self.timeout = config.get('timeout', 10)
        self.max_retries = config.get('max_retries', 3)
        self.retry_delay = config.get('retry_delay', 1)
        
        if not self.endpoint_url:
            logger.error("No endpoint URL specified for HTTP output handler")
    
    def handle(self, logs: List[Dict[str, Any]]) -> None:
        """
        Send logs to an HTTP endpoint.
        
        Args:
            logs: List of log entries to send
        """
        if not self.endpoint_url:
            return
        
        try:
            # Convert logs to JSON
            payload = json.dumps(logs)
            
            # Send the request with retries
            for attempt in range(self.max_retries + 1):
                try:
                    if self.method.upper() == 'POST':
                        response = requests.post(
                            self.endpoint_url,
                            data=payload,
                            headers=self.headers,
                            timeout=self.timeout
                        )
                    elif self.method.upper() == 'PUT':
                        response = requests.put(
                            self.endpoint_url,
                            data=payload,
                            headers=self.headers,
                            timeout=self.timeout
                        )
                    else:
                        logger.error(f"Unsupported HTTP method: {self.method}")
                        return
                    
                    # Check if the request was successful
                    response.raise_for_status()
                    logger.debug(f"Sent {len(logs)} logs to {self.endpoint_url}")
                    break
                    
                except requests.exceptions.RequestException as e:
                    if attempt < self.max_retries:
                        logger.warning(f"HTTP request failed (attempt {attempt+1}/{self.max_retries+1}): {str(e)}")
                        time.sleep(self.retry_delay)
                    else:
                        logger.error(f"HTTP request failed after {self.max_retries+1} attempts: {str(e)}")
            
        except Exception as e:
            logger.error(f"Error sending logs to HTTP endpoint: {str(e)}")


class RedisOutputHandler(BaseOutputHandler):
    """
    Output handler that sends logs to a Redis stream or list.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Redis output handler.
        
        Args:
            config: Dictionary containing configuration parameters
                - host: Redis host
                - port: Redis port
                - db: Redis database number
                - password: Redis password
                - key: Redis key (stream or list name)
                - use_stream: Whether to use Redis streams (True) or lists (False)
                - max_stream_length: Maximum length of the stream
        """
        super().__init__(config)
        self.host = config.get('host', 'localhost')
        self.port = config.get('port', 6379)
        self.db = config.get('db', 0)
        self.password = config.get('password', None)
        self.key = config.get('key', 'logs')
        self.use_stream = config.get('use_stream', True)
        self.max_stream_length = config.get('max_stream_length', 10000)
        
        self.redis_client = None
        self._connect()
    
    def _connect(self):
        """
        Connect to Redis.
        """
        try:
            self.redis_client = redis.Redis(
                host=self.host,
                port=self.port,
                db=self.db,
                password=self.password,
                decode_responses=False  # Keep binary data as is
            )
            self.redis_client.ping()  # Test the connection
            logger.info(f"Connected to Redis at {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"Error connecting to Redis: {str(e)}")
            self.redis_client = None
    
    def handle(self, logs: List[Dict[str, Any]]) -> None:
        """
        Send logs to Redis.
        
        Args:
            logs: List of log entries to send
        """
        if not self.redis_client:
            try:
                self._connect()
                if not self.redis_client:
                    return
            except Exception as e:
                logger.error(f"Error reconnecting to Redis: {str(e)}")
                return
        
        try:
            pipeline = self.redis_client.pipeline()
            
            if self.use_stream:
                # Use Redis streams
                for log in logs:
                    # Convert the log to a dictionary of field-value pairs for the stream
                    fields = {}
                    for key, value in log.items():
                        if isinstance(value, (dict, list)):
                            fields[key] = json.dumps(value)
                        else:
                            fields[key] = str(value)
                    
                    # Add to the stream
                    pipeline.xadd(self.key, fields, maxlen=self.max_stream_length)
            else:
                # Use Redis lists
                for log in logs:
                    pipeline.lpush(self.key, json.dumps(log))
            
            # Execute the pipeline
            pipeline.execute()
            logger.debug(f"Sent {len(logs)} logs to Redis key {self.key}")
            
        except Exception as e:
            logger.error(f"Error sending logs to Redis: {str(e)}")
            self.redis_client = None  # Reset the connection for next attempt


class KafkaOutputHandler(BaseOutputHandler):
    """
    Output handler that sends logs to a Kafka topic.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the Kafka output handler.
        
        Args:
            config: Dictionary containing configuration parameters
                - bootstrap_servers: Comma-separated list of Kafka brokers
                - topic: Kafka topic to send logs to
                - key_field: Field to use as the message key (optional)
                - compression_type: Compression type ('gzip', 'snappy', or None)
                - batch_size: Maximum batch size in bytes
                - linger_ms: Linger time in milliseconds
        """
        super().__init__(config)
        self.bootstrap_servers = config.get('bootstrap_servers', 'localhost:9092')
        self.topic = config.get('topic', 'logs')
        self.key_field = config.get('key_field', None)
        self.compression_type = config.get('compression_type', 'gzip')
        self.batch_size = config.get('batch_size', 16384)
        self.linger_ms = config.get('linger_ms', 100)
        
        self.producer = None
        self._connect()
    
    def _connect(self):
        """
        Connect to Kafka.
        """
        try:
            self.producer = KafkaProducer(
                bootstrap_servers=self.bootstrap_servers,
                compression_type=self.compression_type,
                batch_size=self.batch_size,
                linger_ms=self.linger_ms,
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                key_serializer=lambda k: str(k).encode('utf-8') if k else None
            )
            logger.info(f"Connected to Kafka at {self.bootstrap_servers}")
        except Exception as e:
            logger.error(f"Error connecting to Kafka: {str(e)}")
            self.producer = None
    
    def handle(self, logs: List[Dict[str, Any]]) -> None:
        """
        Send logs to Kafka.
        
        Args:
            logs: List of log entries to send
        """
        if not self.producer:
            try:
                self._connect()
                if not self.producer:
                    return
            except Exception as e:
                logger.error(f"Error reconnecting to Kafka: {str(e)}")
                return
        
        try:
            for log in logs:
                # Extract the key if a key field is specified
                key = log.get(self.key_field) if self.key_field else None
                
                # Send the log to Kafka
                self.producer.send(self.topic, value=log, key=key)
            
            # Flush to ensure all messages are sent
            self.producer.flush()
            logger.debug(f"Sent {len(logs)} logs to Kafka topic {self.topic}")
            
        except Exception as e:
            logger.error(f"Error sending logs to Kafka: {str(e)}")
            self.producer = None  # Reset the connection for next attempt


class AIModelOutputHandler(BaseOutputHandler):
    """
    Output handler that sends logs to the AI model for processing.
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize the AI model output handler.
        
        Args:
            config: Dictionary containing configuration parameters
                - model_endpoint: URL of the AI model endpoint
                - batch_size: Maximum number of logs to send in a single request
                - timeout: Request timeout in seconds
                - headers: Dictionary of HTTP headers
                - include_metadata: Whether to include metadata in the request
        """
        super().__init__(config)
        self.model_endpoint = config.get('model_endpoint', 'http://ml-service:8000/api/v1/predict')
        self.batch_size = config.get('batch_size', 100)
        self.timeout = config.get('timeout', 30)
        self.headers = config.get('headers', {'Content-Type': 'application/json'})
        self.include_metadata = config.get('include_metadata', True)
    
    def handle(self, logs: List[Dict[str, Any]]) -> None:
        """
        Send logs to the AI model.
        
        Args:
            logs: List of log entries to send
        """
        if not logs:
            return
        
        try:
            # Process logs in batches to avoid overwhelming the model
            for i in range(0, len(logs), self.batch_size):
                batch = logs[i:i+self.batch_size]
                
                # Prepare the payload
                payload = {
                    'logs': batch,
                    'metadata': {
                        'batch_size': len(batch),
                        'timestamp': datetime.now().isoformat()
                    } if self.include_metadata else None
                }
                
                # Send the request
                response = requests.post(
                    self.model_endpoint,
                    json=payload,
                    headers=self.headers,
                    timeout=self.timeout
                )
                
                # Check if the request was successful
                response.raise_for_status()
                
                # Log the response
                result = response.json()
                logger.debug(f"AI model processed {len(batch)} logs with result: {result}")
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Error sending logs to AI model: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error in AI model output handler: {str(e)}")