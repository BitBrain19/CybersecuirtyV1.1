"""WebSocket Server for Real-time Streaming Predictions

This module provides a WebSocket server for real-time communication
with clients, enabling live prediction streaming and monitoring.
"""

import json
import asyncio
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any, Set
from dataclasses import asdict
import weakref

import websockets
from websockets.server import WebSocketServerProtocol
from websockets.exceptions import ConnectionClosed, WebSocketException

from .stream_processor import get_stream_processor, PredictionResult
from ..core.exceptions import StreamingError
from ..core.config import get_config

logger = logging.getLogger(__name__)

class WebSocketConnection:
    """Represents a WebSocket connection with metadata."""
    
    def __init__(self, websocket: WebSocketServerProtocol, client_id: str):
        self.websocket = websocket
        self.client_id = client_id
        self.connected_at = datetime.now()
        self.subscriptions: Set[str] = set()
        self.message_count = 0
        self.last_activity = datetime.now()
    
    async def send_message(self, message: Dict[str, Any]) -> bool:
        """Send message to client."""
        try:
            await self.websocket.send(json.dumps(message))
            self.message_count += 1
            self.last_activity = datetime.now()
            return True
        except (ConnectionClosed, WebSocketException) as e:
            logger.warning(f"Failed to send message to {self.client_id}: {str(e)}")
            return False
    
    def subscribe(self, topic: str) -> None:
        """Subscribe to a topic."""
        self.subscriptions.add(topic)
        logger.info(f"Client {self.client_id} subscribed to {topic}")
    
    def unsubscribe(self, topic: str) -> None:
        """Unsubscribe from a topic."""
        self.subscriptions.discard(topic)
        logger.info(f"Client {self.client_id} unsubscribed from {topic}")
    
    def is_subscribed(self, topic: str) -> bool:
        """Check if subscribed to topic."""
        return topic in self.subscriptions

class StreamingWebSocketServer:
    """WebSocket server for streaming predictions."""
    
    def __init__(self, host: str = "localhost", port: int = 8765):
        self.host = host
        self.port = port
        self.config = get_config().get('websocket', {})
        self.stream_processor = get_stream_processor()
        
        # Connection management
        self.connections: Dict[str, WebSocketConnection] = {}
        self.connection_lock = asyncio.Lock()
        
        # Server state
        self.server = None
        self.running = False
        
        # Background tasks
        self.background_tasks: List[asyncio.Task] = []
        
        # Statistics
        self.stats = {
            'total_connections': 0,
            'active_connections': 0,
            'messages_sent': 0,
            'messages_received': 0,
            'start_time': None
        }
        
        logger.info(f"WebSocket server initialized on {host}:{port}")
    
    async def start_server(self) -> None:
        """Start the WebSocket server."""
        if self.running:
            logger.warning("Server already running")
            return
        
        try:
            self.server = await websockets.serve(
                self.handle_client,
                self.host,
                self.port,
                ping_interval=30,
                ping_timeout=10,
                max_size=1024*1024,  # 1MB max message size
                compression=None
            )
            
            self.running = True
            self.stats['start_time'] = datetime.now()
            
            # Start background tasks
            self.background_tasks = [
                asyncio.create_task(self.result_broadcaster()),
                asyncio.create_task(self.connection_monitor()),
                asyncio.create_task(self.stats_updater())
            ]
            
            logger.info(f"WebSocket server started on ws://{self.host}:{self.port}")
            
        except Exception as e:
            logger.error(f"Failed to start WebSocket server: {str(e)}")
            raise StreamingError(f"Server startup failed: {str(e)}")
    
    async def stop_server(self) -> None:
        """Stop the WebSocket server."""
        if not self.running:
            return
        
        self.running = False
        
        # Cancel background tasks
        for task in self.background_tasks:
            task.cancel()
        
        # Wait for tasks to complete
        if self.background_tasks:
            await asyncio.gather(*self.background_tasks, return_exceptions=True)
        
        # Close all connections
        async with self.connection_lock:
            for connection in list(self.connections.values()):
                try:
                    await connection.websocket.close()
                except:
                    pass
            self.connections.clear()
        
        # Close server
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        logger.info("WebSocket server stopped")
    
    async def handle_client(self, websocket: WebSocketServerProtocol, path: str) -> None:
        """Handle new client connection."""
        client_id = f"{websocket.remote_address[0]}:{websocket.remote_address[1]}_{id(websocket)}"
        connection = WebSocketConnection(websocket, client_id)
        
        async with self.connection_lock:
            self.connections[client_id] = connection
            self.stats['total_connections'] += 1
            self.stats['active_connections'] += 1
        
        logger.info(f"New client connected: {client_id}")
        
        # Send welcome message
        await connection.send_message({
            'type': 'welcome',
            'client_id': client_id,
            'server_time': datetime.now().isoformat(),
            'available_topics': ['predictions', 'threat_detection', 'vulnerability_assessment', 'stats']
        })
        
        try:
            async for message in websocket:
                await self.handle_message(connection, message)
                
        except ConnectionClosed:
            logger.info(f"Client {client_id} disconnected")
        except WebSocketException as e:
            logger.warning(f"WebSocket error for {client_id}: {str(e)}")
        except Exception as e:
            logger.error(f"Unexpected error handling {client_id}: {str(e)}")
        finally:
            # Clean up connection
            async with self.connection_lock:
                if client_id in self.connections:
                    del self.connections[client_id]
                    self.stats['active_connections'] -= 1
            
            logger.info(f"Client {client_id} cleaned up")
    
    async def handle_message(self, connection: WebSocketConnection, message: str) -> None:
        """Handle incoming message from client."""
        try:
            data = json.loads(message)
            message_type = data.get('type', 'unknown')
            
            self.stats['messages_received'] += 1
            connection.last_activity = datetime.now()
            
            if message_type == 'subscribe':
                topic = data.get('topic')
                if topic:
                    connection.subscribe(topic)
                    await connection.send_message({
                        'type': 'subscription_confirmed',
                        'topic': topic,
                        'timestamp': datetime.now().isoformat()
                    })
            
            elif message_type == 'unsubscribe':
                topic = data.get('topic')
                if topic:
                    connection.unsubscribe(topic)
                    await connection.send_message({
                        'type': 'unsubscription_confirmed',
                        'topic': topic,
                        'timestamp': datetime.now().isoformat()
                    })
            
            elif message_type == 'predict':
                # Handle direct prediction request
                await self.handle_prediction_request(connection, data)
            
            elif message_type == 'get_stats':
                # Send current statistics
                await connection.send_message({
                    'type': 'stats',
                    'data': await self.get_server_stats(),
                    'timestamp': datetime.now().isoformat()
                })
            
            elif message_type == 'ping':
                # Respond to ping
                await connection.send_message({
                    'type': 'pong',
                    'timestamp': datetime.now().isoformat()
                })
            
            else:
                await connection.send_message({
                    'type': 'error',
                    'message': f'Unknown message type: {message_type}',
                    'timestamp': datetime.now().isoformat()
                })
                
        except json.JSONDecodeError:
            await connection.send_message({
                'type': 'error',
                'message': 'Invalid JSON format',
                'timestamp': datetime.now().isoformat()
            })
        except Exception as e:
            logger.error(f"Error handling message from {connection.client_id}: {str(e)}")
            await connection.send_message({
                'type': 'error',
                'message': 'Internal server error',
                'timestamp': datetime.now().isoformat()
            })
    
    async def handle_prediction_request(self, connection: WebSocketConnection, data: Dict[str, Any]) -> None:
        """Handle direct prediction request."""
        try:
            prediction_data = data.get('data', {})
            model_type = data.get('model_type', 'threat_detection')
            
            # Add to stream processor
            message_id = self.stream_processor.add_message(
                prediction_data,
                model_type,
                source='websocket',
                priority=1
            )
            
            # Wait for result
            start_time = asyncio.get_event_loop().time()
            timeout = 10.0  # 10 second timeout
            
            while asyncio.get_event_loop().time() - start_time < timeout:
                result = self.stream_processor.get_result(timeout=0.1)
                if result and result.message_id == message_id:
                    await connection.send_message({
                        'type': 'prediction_result',
                        'request_id': data.get('request_id'),
                        'result': asdict(result),
                        'timestamp': datetime.now().isoformat()
                    })
                    return
                
                await asyncio.sleep(0.01)
            
            # Timeout
            await connection.send_message({
                'type': 'prediction_timeout',
                'request_id': data.get('request_id'),
                'message': 'Prediction request timed out',
                'timestamp': datetime.now().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Error handling prediction request: {str(e)}")
            await connection.send_message({
                'type': 'prediction_error',
                'request_id': data.get('request_id'),
                'message': str(e),
                'timestamp': datetime.now().isoformat()
            })
    
    async def result_broadcaster(self) -> None:
        """Broadcast prediction results to subscribed clients."""
        logger.info("Started result broadcaster")
        
        while self.running:
            try:
                # Get batch of results
                results = self.stream_processor.get_results_batch(batch_size=10, timeout=1.0)
                
                if not results:
                    await asyncio.sleep(0.1)
                    continue
                
                # Broadcast to subscribed clients
                for result in results:
                    await self.broadcast_result(result)
                
            except Exception as e:
                logger.error(f"Error in result broadcaster: {str(e)}")
                await asyncio.sleep(1.0)
        
        logger.info("Stopped result broadcaster")
    
    async def broadcast_result(self, result: PredictionResult) -> None:
        """Broadcast a single result to subscribed clients."""
        message = {
            'type': 'prediction_broadcast',
            'result': asdict(result),
            'timestamp': datetime.now().isoformat()
        }
        
        # Determine topics
        topics = ['predictions', result.model_name]
        
        # Send to subscribed clients
        async with self.connection_lock:
            disconnected_clients = []
            
            for client_id, connection in self.connections.items():
                try:
                    # Check if client is subscribed to any relevant topic
                    if any(connection.is_subscribed(topic) for topic in topics):
                        success = await connection.send_message(message)
                        if success:
                            self.stats['messages_sent'] += 1
                        else:
                            disconnected_clients.append(client_id)
                            
                except Exception as e:
                    logger.error(f"Error sending to {client_id}: {str(e)}")
                    disconnected_clients.append(client_id)
            
            # Clean up disconnected clients
            for client_id in disconnected_clients:
                if client_id in self.connections:
                    del self.connections[client_id]
                    self.stats['active_connections'] -= 1
    
    async def connection_monitor(self) -> None:
        """Monitor connections and clean up stale ones."""
        logger.info("Started connection monitor")
        
        while self.running:
            try:
                await asyncio.sleep(30)  # Check every 30 seconds
                
                current_time = datetime.now()
                stale_connections = []
                
                async with self.connection_lock:
                    for client_id, connection in self.connections.items():
                        # Check for stale connections (no activity for 5 minutes)
                        if (current_time - connection.last_activity).total_seconds() > 300:
                            stale_connections.append(client_id)
                    
                    # Clean up stale connections
                    for client_id in stale_connections:
                        try:
                            connection = self.connections[client_id]
                            await connection.websocket.close()
                            del self.connections[client_id]
                            self.stats['active_connections'] -= 1
                            logger.info(f"Cleaned up stale connection: {client_id}")
                        except Exception as e:
                            logger.error(f"Error cleaning up {client_id}: {str(e)}")
                
            except Exception as e:
                logger.error(f"Error in connection monitor: {str(e)}")
        
        logger.info("Stopped connection monitor")
    
    async def stats_updater(self) -> None:
        """Update server statistics periodically."""
        while self.running:
            try:
                await asyncio.sleep(60)  # Update every minute
                
                # Broadcast stats to subscribed clients
                stats_message = {
                    'type': 'stats_update',
                    'data': await self.get_server_stats(),
                    'timestamp': datetime.now().isoformat()
                }
                
                async with self.connection_lock:
                    for connection in self.connections.values():
                        if connection.is_subscribed('stats'):
                            await connection.send_message(stats_message)
                
            except Exception as e:
                logger.error(f"Error in stats updater: {str(e)}")
    
    async def get_server_stats(self) -> Dict[str, Any]:
        """Get comprehensive server statistics."""
        processor_stats = self.stream_processor.get_stats()
        
        uptime = None
        if self.stats['start_time']:
            uptime = (datetime.now() - self.stats['start_time']).total_seconds()
        
        return {
            'websocket_server': {
                'running': self.running,
                'uptime_seconds': uptime,
                'total_connections': self.stats['total_connections'],
                'active_connections': self.stats['active_connections'],
                'messages_sent': self.stats['messages_sent'],
                'messages_received': self.stats['messages_received']
            },
            'stream_processor': processor_stats,
            'timestamp': datetime.now().isoformat()
        }
    
    async def broadcast_message(self, message: Dict[str, Any], topic: str = 'general') -> int:
        """Broadcast a message to all clients subscribed to a topic."""
        sent_count = 0
        
        async with self.connection_lock:
            for connection in self.connections.values():
                if connection.is_subscribed(topic):
                    success = await connection.send_message(message)
                    if success:
                        sent_count += 1
                        self.stats['messages_sent'] += 1
        
        return sent_count

# Global server instance
_server_instance: Optional[StreamingWebSocketServer] = None

def get_websocket_server(host: str = "localhost", port: int = 8765) -> StreamingWebSocketServer:
    """Get global WebSocket server instance."""
    global _server_instance
    if _server_instance is None:
        _server_instance = StreamingWebSocketServer(host, port)
    return _server_instance

async def start_streaming_server(host: str = "localhost", port: int = 8765) -> StreamingWebSocketServer:
    """Start the streaming WebSocket server."""
    server = get_websocket_server(host, port)
    await server.start_server()
    return server