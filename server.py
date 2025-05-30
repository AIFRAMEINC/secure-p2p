# server.py - FastAPI Server for Secure Messaging - WebSocket Relay
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Optional, List
import sqlite3
import uuid
import json
import asyncio
from datetime import datetime, timedelta
import logging
import os
import uvicorn

# Configure logging based on environment
DEBUG_MODE = os.getenv('DEBUG', 'False').lower() == 'true'

if DEBUG_MODE:
    logging.basicConfig(level=logging.INFO)
else:
    logging.basicConfig(level=logging.WARNING)  # Only warnings and errors in production

logger = logging.getLogger(__name__)

# Reduce uvicorn logging
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)

app = FastAPI(title="Secure Messaging Server", version="2.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Data models
class ClientRegistration(BaseModel):
    client_name: str
    rsa_public_key: str
    ecc_public_key: str
    dh_public_key: str  # کلید عمومی DH

class ClientIdRegeneration(BaseModel):
    old_client_id: str
    client_name: str
    rsa_public_key: str
    ecc_public_key: str
    dh_public_key: str  # کلید عمومی DH

class ClientInfo(BaseModel):
    client_id: str
    client_name: str
    ip_address: str
    port: int
    rsa_public_key: str
    ecc_public_key: str
    dh_public_key: str  # کلید عمومی DH
    last_seen: datetime

class MessageRequest(BaseModel):
    sender_id: str
    recipient_id: str
    encrypted_message: str

# In-memory storage for active clients
active_clients: Dict[str, ClientInfo] = {}
websocket_connections: Dict[str, WebSocket] = {}

class DatabaseManager:
    def __init__(self, db_path: str = "secure_messaging.db"):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Initialize the database with required tables"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Clients table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                client_id TEXT PRIMARY KEY,
                client_name TEXT NOT NULL,
                rsa_public_key TEXT NOT NULL,
                ecc_public_key TEXT NOT NULL,
                dh_public_key TEXT NOT NULL, -- ستون برای کلید DH
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_active TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                revoked_at TIMESTAMP NULL
            )
        ''')
        
        # Active sessions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS active_sessions (
                client_id TEXT PRIMARY KEY,
                ip_address TEXT,
                port INTEGER,
                session_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (client_id) REFERENCES clients (client_id)
            )
        ''')
        
        conn.commit()
        conn.close()
        
    def register_client(self, client_name: str, rsa_key: str, ecc_key: str, dh_key: str) -> str:
        client_id = str(uuid.uuid4())
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO clients (client_id, client_name, rsa_public_key, ecc_public_key, dh_public_key)
            VALUES (?, ?, ?, ?, ?)
        ''', (client_id, client_name, rsa_key, ecc_key, dh_key))
        
        conn.commit()
        conn.close()
        
        if DEBUG_MODE:
            logger.info(f"Client registered: {client_id} - {client_name}")
        return client_id

    def get_client_keys(self, client_id: str) -> Optional[tuple]:
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT rsa_public_key, ecc_public_key, dh_public_key FROM clients 
            WHERE client_id = ? AND revoked_at IS NULL
        ''', (client_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        return result

    def create_session(self, client_id: str, ip: str, port: int):
        """Create an active session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO active_sessions 
            (client_id, ip_address, port) VALUES (?, ?, ?)
        ''', (client_id, ip, port))
        
        conn.commit()
        conn.close()

    def remove_session(self, client_id: str):
        """Remove active session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM active_sessions WHERE client_id = ?', (client_id,))
        
        conn.commit()
        conn.close()

    def regenerate_client_id(self, old_client_id: str, client_name: str, rsa_key: str, ecc_key: str, dh_key: str) -> str:
        new_client_id = str(uuid.uuid4())
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                UPDATE clients 
                SET revoked_at = CURRENT_TIMESTAMP 
                WHERE client_id = ?
            ''', (old_client_id,))
            
            cursor.execute('''
                INSERT INTO clients (client_id, client_name, rsa_public_key, ecc_public_key, dh_public_key)
                VALUES (?, ?, ?, ?, ?)
            ''', (new_client_id, client_name, rsa_key, ecc_key, dh_key))
            
            cursor.execute('''
                DELETE FROM active_sessions WHERE client_id = ?
            ''', (old_client_id,))
            
            conn.commit()
            
            if DEBUG_MODE:
                logger.info(f"Client ID regenerated in DB: {old_client_id} → {new_client_id}")
            return new_client_id
            
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error in regenerate_client_id: {e}")
            raise e
        finally:
            conn.close()

    def get_client_name(self, client_id: str) -> Optional[str]:
        """Get client name by ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT client_name FROM clients WHERE client_id = ? AND revoked_at IS NULL
        ''', (client_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        return result[0] if result else None

# Initialize database
db_manager = DatabaseManager()

@app.post("/register")
async def register_client(registration: ClientRegistration):
    try:
        client_id = db_manager.register_client(
            registration.client_name,
            registration.rsa_public_key,
            registration.ecc_public_key,
            registration.dh_public_key
        )
        
        return {
            "success": True,
            "client_id": client_id,
            "message": "Client registered successfully"
        }
    except Exception as e:
        logger.error(f"Registration error: {str(e)}")
        raise HTTPException(status_code=500, detail="Registration failed")

@app.post("/regenerate_id")
async def regenerate_client_id(regeneration: ClientIdRegeneration):
    try:
        old_keys = db_manager.get_client_keys(regeneration.old_client_id)
        if not old_keys:
            raise HTTPException(status_code=404, detail="Old client ID not found")
        
        if DEBUG_MODE:
            logger.info(f"Regenerating ID for client: {regeneration.old_client_id}")
        
        new_client_id = db_manager.regenerate_client_id(
            regeneration.old_client_id,
            regeneration.client_name,
            regeneration.rsa_public_key,
            regeneration.ecc_public_key,
            regeneration.dh_public_key
        )
        
        if regeneration.old_client_id in active_clients:
            if DEBUG_MODE:
                logger.info(f"Removing old client from active list: {regeneration.old_client_id}")
            del active_clients[regeneration.old_client_id]
        
        if regeneration.old_client_id in websocket_connections:
            try:
                await websocket_connections[regeneration.old_client_id].close()
                del websocket_connections[regeneration.old_client_id]
                if DEBUG_MODE:
                    logger.info(f"Closed old WebSocket connection: {regeneration.old_client_id}")
            except Exception as e:
                logger.error(f"Error closing old WebSocket: {e}")
        
        if DEBUG_MODE:
            logger.info(f"Client ID regenerated: {regeneration.old_client_id} → {new_client_id}")
        
        return {
            "success": True,
            "new_client_id": new_client_id,
            "old_client_id": regeneration.old_client_id,
            "message": "Client ID regenerated successfully"
        }
    except Exception as e:
        logger.error(f"ID Regeneration error: {str(e)}")
        raise HTTPException(status_code=500, detail="ID regeneration failed")

@app.post("/connect")
async def connect_client(client_id: str, ip_address: str, port: int):
    try:
        keys = db_manager.get_client_keys(client_id)
        if not keys:
            raise HTTPException(status_code=404, detail="Client not found")
        
        client_name = db_manager.get_client_name(client_id)
        
        db_manager.create_session(client_id, ip_address, port)
        
        active_clients[client_id] = ClientInfo(
            client_id=client_id,
            client_name=client_name or "Unknown",
            ip_address=ip_address,
            port=port,
            rsa_public_key=keys[0],
            ecc_public_key=keys[1],
            dh_public_key=keys[2],
            last_seen=datetime.now()
        )
        
        if DEBUG_MODE:
            logger.info(f"Client connected: {client_id} at {ip_address}:{port}")
        
        return {
            "success": True,
            "message": "Connected successfully",
            "active_clients": len(active_clients)
        }
    except Exception as e:
        logger.error(f"Connection error: {str(e)}")
        raise HTTPException(status_code=500, detail="Connection failed")

@app.post("/disconnect")
async def disconnect_client(client_id: str):
    """Disconnect a client from the network"""
    try:
        # Remove from active clients
        if client_id in active_clients:
            del active_clients[client_id]
        
        # Remove session from database
        db_manager.remove_session(client_id)
        
        # Close websocket if exists
        if client_id in websocket_connections:
            await websocket_connections[client_id].close()
            del websocket_connections[client_id]
        
        if DEBUG_MODE:
            logger.info(f"Client disconnected: {client_id}")
        
        return {
            "success": True,
            "message": "Disconnected successfully"
        }
    except Exception as e:
        logger.error(f"Disconnect error: {str(e)}")
        raise HTTPException(status_code=500, detail="Disconnect failed")

@app.get("/find_client/{client_id}")
async def find_client(client_id: str):
    if client_id not in active_clients:
        raise HTTPException(status_code=404, detail="Client not found or offline")
    
    client_info = active_clients[client_id]
    
    return {
        "success": True,
        "client_info": {
            "client_id": client_info.client_id,
            "client_name": client_info.client_name,
            "ip_address": client_info.ip_address,
            "port": client_info.port,
            "rsa_public_key": client_info.rsa_public_key,
            "ecc_public_key": client_info.ecc_public_key,
            "dh_public_key": client_info.dh_public_key
        }
    }

@app.get("/active_clients")
async def get_active_clients():
    """Get list of all active clients"""
    return {
        "success": True,
        "count": len(active_clients),
        "clients": [
            {
                "client_id": client_id,
                "client_name": client_info.client_name,
                "ip_address": client_info.ip_address,
                "port": client_info.port,
                "last_seen": client_info.last_seen.isoformat()
            }
            for client_id, client_info in active_clients.items()
        ]
    }

@app.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """WebSocket endpoint for message relaying"""
    try:
        await websocket.accept()
        websocket_connections[client_id] = websocket
        if DEBUG_MODE:
            logger.info(f"WebSocket connected for client: {client_id}")

        # Update last seen
        if client_id in active_clients:
            active_clients[client_id].last_seen = datetime.now()

        while True:
            try:
                data = await websocket.receive_text()
                message = json.loads(data)

                if message["type"] == "register":
                    if message.get("client_id") == client_id:
                        if DEBUG_MODE:
                            logger.info(f"Client registered via WebSocket: {client_id}")
                        await websocket.send_text(json.dumps({
                            "type": "register_ack",
                            "success": True
                        }))
                    else:
                        await websocket.send_text(json.dumps({
                            "type": "error",
                            "message": "Invalid client_id"
                        }))

                elif message["type"] == "message":
                    recipient_id = message.get("recipient_id")
                    if recipient_id in websocket_connections:
                        try:
                            await websocket_connections[recipient_id].send_text(json.dumps({
                                "type": "message",
                                "sender_id": message.get("sender_id"),
                                "encrypted_message": message.get("encrypted_message"),
                                "timestamp": message.get("timestamp")
                            }))
                            if DEBUG_MODE:
                                logger.info(f"Message forwarded from {message.get('sender_id')} to {recipient_id}")
                            await websocket.send_text(json.dumps({
                                "type": "message_ack",
                                "success": True
                            }))
                        except Exception as e:
                            logger.error(f"Error forwarding message: {e}")
                            await websocket.send_text(json.dumps({
                                "type": "error",
                                "message": f"Failed to forward message to {recipient_id}"
                            }))
                            if recipient_id in websocket_connections:
                                del websocket_connections[recipient_id]
                    else:
                        await websocket.send_text(json.dumps({
                            "type": "error",
                            "message": f"Recipient {recipient_id} not found"
                        }))
                        if DEBUG_MODE:
                            logger.warning(f"Recipient {recipient_id} not found")

                elif message["type"] == "heartbeat":
                    await websocket.send_text(json.dumps({
                        "type": "heartbeat_ack",
                        "timestamp": datetime.now().isoformat()
                    }))
                    if client_id in active_clients:
                        active_clients[client_id].last_seen = datetime.now()

                else:
                    await websocket.send_text(json.dumps({
                        "type": "error",
                        "message": "Invalid message type"
                    }))

            except WebSocketDisconnect:
                break
            except Exception as e:
                logger.error(f"WebSocket message error: {e}")
                break

    except Exception as e:
        logger.error(f"WebSocket connection error: {e}")

    finally:
        if client_id in websocket_connections:
            del websocket_connections[client_id]
        if DEBUG_MODE:
            logger.info(f"WebSocket disconnected: {client_id}")

@app.on_event("startup")
async def startup_event():
    if DEBUG_MODE:
        logger.info("Starting Secure Messaging Server...")
    asyncio.create_task(cleanup_inactive_clients())

async def cleanup_inactive_clients():
    """Remove clients that haven't been seen for a while"""
    while True:
        await asyncio.sleep(120)  # Check every 2 minutes

        current_time = datetime.now()
        inactive_clients = []

        for client_id, client_info in active_clients.items():
            if current_time - client_info.last_seen > timedelta(minutes=10):
                inactive_clients.append(client_id)

        for client_id in inactive_clients:
            if DEBUG_MODE:
                logger.info(f"Removing inactive client: {client_id}")
            del active_clients[client_id]
            db_manager.remove_session(client_id)

            if client_id in websocket_connections:
                try:
                    await websocket_connections[client_id].close()
                except:
                    pass
                del websocket_connections[client_id]

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "active_clients": len(active_clients),
        "websocket_connections": len(websocket_connections),
        "timestamp": datetime.now().isoformat()
    }

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Secure Messaging Server",
        "version": "2.0.0",
        "status": "running",
        "active_clients": len(active_clients)
    }

if __name__ == "__main__":
    uvicorn.run(
        "server:app",
        host="0.0.0.0",
        port=8000,
        reload=DEBUG_MODE,
        access_log=DEBUG_MODE,
        #ssl_keyfile="/root/hid/key.pem",  # مسیر فایل کلید خصوصی SSL
        #ssl_certfile="/root/hid/cert.pem"  # مسیر فایل گواهینامه SSL
    )