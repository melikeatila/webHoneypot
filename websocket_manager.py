
"""
WebSocket Connection Manager for Real-time Updates
Manages multiple WebSocket connections and broadcasts events
"""
from fastapi import WebSocket, WebSocketDisconnect
from typing import List, Dict, Any
import json
import logging
import asyncio
from datetime import datetime

logger = logging.getLogger(__name__)


class ConnectionManager:
    """
    Manages WebSocket connections and broadcasts messages to all connected clients
    """
    
    def __init__(self):
        
        self.active_connections: List[WebSocket] = []
        
        self.connection_info: Dict[WebSocket, Dict[str, Any]] = {}
        
    async def connect(self, websocket: WebSocket, client_id: str = None):
        """
        Accept a new WebSocket connection
        
        Args:
            websocket: FastAPI WebSocket instance
            client_id: Optional client identifier
        """
        await websocket.accept()
        self.active_connections.append(websocket)
        
        
        self.connection_info[websocket] = {
            "client_id": client_id or f"client_{len(self.active_connections)}",
            "connected_at": datetime.utcnow().isoformat(),
            "ip": websocket.client.host if websocket.client else "unknown"
        }
        
        logger.info(f"WebSocket connected: {self.connection_info[websocket]['client_id']} "
                   f"from {self.connection_info[websocket]['ip']} "
                   f"(Total: {len(self.active_connections)})")
        
        
        await self.send_personal_message({
            "type": "connected",
            "message": "Connected to honeypot real-time updates",
            "timestamp": datetime.utcnow().isoformat()
        }, websocket)
    
    def disconnect(self, websocket: WebSocket):
        """
        Remove a WebSocket connection
        
        Args:
            websocket: FastAPI WebSocket instance
        """
        if websocket in self.active_connections:
            client_info = self.connection_info.get(websocket, {})
            self.active_connections.remove(websocket)
            self.connection_info.pop(websocket, None)
            
            logger.info(f"WebSocket disconnected: {client_info.get('client_id', 'unknown')} "
                       f"(Total: {len(self.active_connections)})")
    
    async def send_personal_message(self, message: Dict[str, Any], websocket: WebSocket):
        """
        Send a message to a specific client
        
        Args:
            message: Dictionary to send (will be JSON serialized)
            websocket: Target WebSocket connection
        """
        try:
            await websocket.send_json(message)
        except Exception as e:
            logger.error(f"Error sending personal message: {e}")
            self.disconnect(websocket)
    
    async def broadcast(self, message: Dict[str, Any]):
        """
        Broadcast a message to all connected clients
        
        Args:
            message: Dictionary to broadcast (will be JSON serialized)
        """
        if not self.active_connections:
            logger.debug("No active connections to broadcast to")
            return
        
        
        if "timestamp" not in message:
            message["timestamp"] = datetime.utcnow().isoformat()
        
        logger.debug(f"Broadcasting to {len(self.active_connections)} clients: {message.get('type', 'unknown')}")
        
        
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except WebSocketDisconnect:
                disconnected.append(connection)
            except Exception as e:
                logger.error(f"Error broadcasting to client: {e}")
                disconnected.append(connection)
        
        
        for conn in disconnected:
            self.disconnect(conn)
    
    async def broadcast_event(self, event_type: str, data: Dict[str, Any]):
        """
        Broadcast an event with specific type
        
        Args:
            event_type: Type of event (e.g., 'bait_click', 'admin_attempt', 'anomaly')
            data: Event data
        """
        message = {
            "type": event_type,
            "data": data,
            "timestamp": datetime.utcnow().isoformat()
        }
        await self.broadcast(message)
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get connection statistics
        
        Returns:
            Dictionary with connection stats
        """
        return {
            "total_connections": len(self.active_connections),
            "connections": [
                {
                    "client_id": info["client_id"],
                    "ip": info["ip"],
                    "connected_at": info["connected_at"]
                }
                for info in self.connection_info.values()
            ]
        }
    
    async def heartbeat(self):
        """
        Send periodic heartbeat to all connections to keep them alive
        """
        while True:
            await asyncio.sleep(30)  
            if self.active_connections:
                await self.broadcast({
                    "type": "heartbeat",
                    "message": "ping",
                    "connections": len(self.active_connections)
                })



manager = ConnectionManager()




async def broadcast_bait_click(ip: str, path: str, user_agent: str = None):
    """Broadcast a bait click event"""
    await manager.broadcast_event("bait_click", {
        "ip": ip,
        "path": path,
        "user_agent": user_agent,
        "severity": "high"
    })


async def broadcast_admin_attempt(ip: str, username: str, success: bool = False):
    """Broadcast an admin login attempt"""
    await manager.broadcast_event("admin_attempt", {
        "ip": ip,
        "username": username,
        "success": success,
        "severity": "critical" if not success else "info"
    })


async def broadcast_anomaly(ip: str, anomaly_score: float, details: Dict[str, Any] = None):
    """Broadcast an anomaly detection"""
    await manager.broadcast_event("anomaly_detected", {
        "ip": ip,
        "score": anomaly_score,
        "details": details or {},
        "severity": "critical" if anomaly_score < -0.7 else "high"
    })


async def broadcast_upload(ip: str, filename: str, file_size: int):
    """Broadcast a file upload event"""
    await manager.broadcast_event("file_upload", {
        "ip": ip,
        "filename": filename,
        "file_size": file_size,
        "severity": "medium"
    })


async def broadcast_stats_update(stats: Dict[str, Any]):
    """Broadcast stats update"""
    await manager.broadcast_event("stats_update", stats)
