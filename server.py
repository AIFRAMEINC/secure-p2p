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
from cryptography.fernet import Fernet

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

# تولید یک کلید AES (این باید به صورت امن ذخیره شود، مثلاً در یک متغیر محیطی)
AES_KEY = Fernet.generate_key()
cipher = Fernet(AES_KEY)

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
    dh_public_key: str

class ClientIdRegeneration(BaseModel):
    old_client_id: str
    client_name: str
    rsa_public_key: str
    ecc_public_key: str
    dh_public_key: str

class ClientInfo(BaseModel):
    client_id: str
    client_name: str
    ip_address: str
    port: int
    udp_port: Optional[int] = None  # اضافه کردن پورت UDP
    rsa_public_key: str
    ecc_public_key: str
    dh_public_key: str
    last_seen: datetime

class MessageRequest(BaseModel):
    sender_id: str
    recipient_id: str
    encrypted_message: str

class UpdateKeysRequest(BaseModel):
    client_id: str
    dh_public_key: str
    dh_signature: str

# In-memory storage for active clients and nonces
active_clients: Dict[str, ClientInfo] = {}
websocket_connections: Dict[str, WebSocket] = {}
used_nonces: set = set()

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
                dh_public_key TEXT NOT NULL,
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
        
        # DH key history table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dh_key_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT NOT NULL,
                dh_public_key TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (client_id) REFERENCES clients (client_id)
            )
        ''')
        
        # جدول جدید برای ذخیره موقت تکه‌های فایل
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS file_transfers (
                file_id TEXT NOT NULL,
                sender_id TEXT NOT NULL,
                recipient_id TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                chunk_data TEXT NOT NULL,
                total_chunks INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (file_id, chunk_index),
                FOREIGN KEY (sender_id) REFERENCES clients (client_id),
                FOREIGN KEY (recipient_id) REFERENCES clients (client_id)
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
        """Create an active session with encrypted IP address"""
        encrypted_ip = cipher.encrypt(ip.encode()).decode()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO active_sessions 
            (client_id, ip_address, port) VALUES (?, ?, ?)
        ''', (client_id, encrypted_ip, port))
        
        conn.commit()
        conn.close()

    def remove_session(self, client_id: str):
        """Remove active session"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('DELETE FROM active_sessions WHERE client_id = ?', (client_id,))
        
        conn.commit()
        conn.close()

    def cleanup_old_sessions(self):
        """Remove sessions older than 24 hours"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                DELETE FROM active_sessions
                WHERE session_start < datetime('now', '-24 hours')
            ''')
            deleted_count = cursor.rowcount
            conn.commit()
            if DEBUG_MODE and deleted_count > 0:
                logger.info(f"Deleted {deleted_count} old sessions from active_sessions")
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error in cleanup_old_sessions: {e}")
            raise e
        finally:
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

    def store_old_dh_key(self, client_id: str, dh_public_key: str):
        """Store the old DH public key in history before updating"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT INTO dh_key_history (client_id, dh_public_key)
                VALUES (?, ?)
            ''', (client_id, dh_public_key))
            conn.commit()
            if DEBUG_MODE:
                logger.info(f"Stored old DH public key for client: {client_id}")
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error in store_old_dh_key: {e}")
            raise e
        finally:
            conn.close()

    def cleanup_old_dh_keys(self):
        """Remove DH keys older than 24 hours"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                DELETE FROM dh_key_history
                WHERE created_at < datetime('now', '-24 hours')
            ''')
            deleted_count = cursor.rowcount
            conn.commit()
            if DEBUG_MODE and deleted_count > 0:
                logger.info(f"Deleted {deleted_count} old DH keys from history")
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error in cleanup_old_dh_keys: {e}")
            raise e
        finally:
            conn.close()

    def update_client_dh_key(self, client_id: str, dh_public_key: str, dh_signature: str, ecc_public_key: str):
        """Update the DH public key for a client after verifying signature"""
        import base64
        from ecdsa import VerifyingKey, BadSignatureError
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # دریافت کلید عمومی ECC برای تأیید امضا
            cursor.execute('''
                SELECT ecc_public_key FROM clients 
                WHERE client_id = ? AND revoked_at IS NULL
            ''', (client_id,))
            result = cursor.fetchone()
            if not result:
                raise HTTPException(status_code=404, detail="Client not found or revoked")
            
            ecc_public_key = result[0]
            
            # تأیید امضای کلید DH با ECC
            try:
                vk = VerifyingKey.from_pem(ecc_public_key)
                if not vk.verify(bytes.fromhex(dh_signature), dh_public_key.encode('utf-8')):
                    raise HTTPException(status_code=403, detail="Invalid DH key signature")
            except BadSignatureError:
                raise HTTPException(status_code=403, detail="Invalid DH key signature")
            except Exception as e:
                logger.error(f"Signature verification error: {e}")
                raise HTTPException(status_code=500, detail="Signature verification failed")

            # ذخیره کلید فعلی DH در تاریخچه قبل از به‌روزرسانی
            cursor.execute('''
                SELECT dh_public_key FROM clients WHERE client_id = ?
            ''', (client_id,))
            current_dh_key = cursor.fetchone()
            if current_dh_key:
                self.store_old_dh_key(client_id, current_dh_key[0])

            # به‌روزرسانی کلید جدید
            cursor.execute('''
                UPDATE clients 
                SET dh_public_key = ?, last_active = CURRENT_TIMESTAMP 
                WHERE client_id = ? AND revoked_at IS NULL
            ''', (dh_public_key, client_id))
            
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Client not found or revoked")
            
            conn.commit()
            if DEBUG_MODE:
                logger.info(f"Updated DH public key for client in DB: {client_id}")
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error in update_client_dh_key: {e}")
            raise e
        finally:
            conn.close()

    def store_file_chunk(self, file_id: str, sender_id: str, recipient_id: str, chunk_index: int, chunk_data: str, total_chunks: int):
        """Store a file chunk in the database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO file_transfers 
                (file_id, sender_id, recipient_id, chunk_index, chunk_data, total_chunks)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (file_id, sender_id, recipient_id, chunk_index, chunk_data, total_chunks))
            conn.commit()
            if DEBUG_MODE:
                logger.info(f"Stored file chunk {chunk_index} for file {file_id}")
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error in store_file_chunk: {e}")
            raise e
        finally:
            conn.close()

    def get_missing_chunks(self, file_id: str, received_chunks: int) -> List[dict]:
        """Retrieve missing chunks for a file transfer"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT chunk_index, chunk_data, total_chunks
                FROM file_transfers
                WHERE file_id = ? AND chunk_index >= ?
                ORDER BY chunk_index
            ''', (file_id, received_chunks))
            chunks = cursor.fetchall()
            return [{"chunk_index": row[0], "chunk_data": row[1], "total_chunks": row[2]} for row in chunks]
        finally:
            conn.close()

    def cleanup_old_file_transfers(self):
        """Remove file transfers older than 24 hours"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                DELETE FROM file_transfers
                WHERE created_at < datetime('now', '-24 hours')
            ''')
            deleted_count = cursor.rowcount
            conn.commit()
            if DEBUG_MODE and deleted_count > 0:
                logger.info(f"Deleted {deleted_count} old file transfers")
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error in cleanup_old_file_transfers: {e}")
            raise e
        finally:
            conn.close()

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
async def connect_client(client_id: str, ip_address: str, port: int, udp_port: Optional[int] = None):
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
            udp_port=udp_port,  # ذخیره پورت UDP
            rsa_public_key=keys[0],
            ecc_public_key=keys[1],
            dh_public_key=keys[2],
            last_seen=datetime.now()
        )
        
        if DEBUG_MODE:
            logger.info(f"Client connected: {client_id} at {ip_address}:{port}, UDP port: {udp_port}")
        
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

@app.post("/update_keys")
async def update_keys(request: UpdateKeysRequest):
    try:
        # Update DH public key in database after verifying signature
        if not request.client_id in active_clients:
            raise HTTPException(status_code=404, detail="Client not found")
        
        client_info = active_clients[request.client_id]
        db_manager.update_client_dh_key(
            request.client_id,
            request.dh_public_key,
            request.dh_signature,
            client_info.ecc_public_key
        )
        
        # Update in-memory active clients
        if request.client_id in active_clients:
            active_clients[request.client_id].dh_public_key = request.dh_public_key
            active_clients[request.client_id].last_seen = datetime.now()
        
        if DEBUG_MODE:
            logger.info(f"DH public key updated for client: {request.client_id}")
        
        return {
            "success": True,
            "message": "DH public key updated successfully"
        }
    except Exception as e:
        logger.error(f"Update keys error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to update DH public key")

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
            "udp_port": client_info.udp_port,  # ارسال پورت UDP
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
    try:
        await websocket.accept()
        websocket_connections[client_id] = websocket
        if DEBUG_MODE:
            logger.info(f"WebSocket connected for client: {client_id}")

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
                    if "nonce" not in message:
                        await websocket.send_text(json.dumps({
                            "type": "error",
                            "message": "Message nonce missing"
                        }))
                        continue

                    if message["nonce"] in used_nonces:
                        await websocket.send_text(json.dumps({
                            "type": "error",
                            "message": "Replay attack detected: nonce already used"
                        }))
                        continue
                    used_nonces.add(message["nonce"])

                    recipient_id = message.get("recipient_id")
                    if recipient_id in websocket_connections:
                        try:
                            # ارسال پیام بدون رمزگشایی، شامل MAC
                            await websocket_connections[recipient_id].send_text(json.dumps({
                                "type": "message",
                                "sender_id": message.get("sender_id"),
                                "encrypted_message": message.get("encrypted_message"),
                                "timestamp": message.get("timestamp"),
                                "dh_public_key": message.get("dh_public_key"),
                                "nonce": message["nonce"]
                            }))
                            if DEBUG_MODE:
                                logger.info(f"Message with MAC forwarded from {message.get('sender_id')} to {recipient_id}")
                            await websocket.send_text(json.dumps({
                                "type": "message_ack",
                                "success": True
                            }))
                        except Exception as e:
                            logger.error(f"Error forwarding message: {e}")
                            await websocket.send_text(json.dumps({
                                "type": "error",
                                "message": f"Failed to forward message to {recipient_id} due to connection issue"
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

                elif message["type"] == "update_keys":
                    client_id = message.get("client_id")
                    dh_public_key = message.get("dh_public_key")
                    dh_signature = message.get("dh_signature")
                    if client_id in active_clients and dh_public_key and dh_signature:
                        db_manager.update_client_dh_key(client_id, dh_public_key, dh_signature, active_clients[client_id].ecc_public_key)
                        active_clients[client_id].dh_public_key = dh_public_key
                        if DEBUG_MODE:
                            logger.info(f"Updated DH public key for client: {client_id}")
                        await websocket.send_text(json.dumps({
                            "type": "update_keys_ack",
                            "success": True
                        }))
                    else:
                        await websocket.send_text(json.dumps({
                            "type": "error",
                            "message": "Invalid client or DH key"
                        }))

                elif message["type"] == "heartbeat":
                    await websocket.send_text(json.dumps({
                        "type": "heartbeat_ack",
                        "timestamp": datetime.now().isoformat()
                    }))
                    if client_id in active_clients:
                        active_clients[client_id].last_seen = datetime.now()

                elif message["type"] == "pd_ack":
                    recipient_id = message.get("recipient_id")
                    if "nonce" not in message:
                        await websocket.send_text(json.dumps({
                            "type": "error",
                            "message": "Message nonce missing"
                        }))
                        continue
                    if message["nonce"] in used_nonces:
                        await websocket.send_text(json.dumps({
                            "type": "error",
                            "message": "Replay attack detected: nonce already used"
                        }))
                        continue
                    used_nonces.add(message["nonce"])

                    if recipient_id in websocket_connections:
                        await websocket_connections[recipient_id].send_text(json.dumps({
                            "type": "pd_ack",
                            "sender_id": message.get("sender_id"),
                            "timestamp": message.get("timestamp"),
                            "nonce": message["nonce"]
                        }))
                        if DEBUG_MODE:
                            logger.info(f"PD acknowledgment forwarded from {message.get('sender_id')} to {recipient_id}")

                elif message["type"] == "request_missing_chunks":
                    file_id = message.get("fileId")
                    received_chunks = message.get("received_chunks")
                    sender_id = message.get("sender_id")
                    recipient_id = message.get("recipient_id")

                    if "nonce" not in message:
                        await websocket.send_text(json.dumps({
                            "type": "error",
                            "message": "Message nonce missing"
                        }))
                        continue
                    if message["nonce"] in used_nonces:
                        await websocket.send_text(json.dumps({
                            "type": "error",
                            "message": "Replay attack detected: nonce already used"
                        }))
                        continue
                    used_nonces.add(message["nonce"])

                    missing_chunks = db_manager.get_missing_chunks(file_id, received_chunks)
                    for chunk in missing_chunks:
                        chunk_message = {
                            "type": "file_chunk",
                            "fileId": file_id,
                            "chunkIndex": chunk["chunk_index"],
                            "chunkData": chunk["chunk_data"],
                            "isLastChunk": chunk["chunk_index"] == chunk["total_chunks"] - 1
                        }
                        await websocket.send_text(json.dumps({
                            "type": "message",
                            "sender_id": sender_id,
                            "recipient_id": recipient_id,
                            "encrypted_message": json.dumps(chunk_message),
                            "timestamp": datetime.now().isoformat(),
                            "nonce": message["nonce"]
                        }))
                        if DEBUG_MODE:
                            logger.info(f"Sent missing chunk {chunk['chunk_index']} for file {file_id}")

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

class UDPServerProtocol:
    def __init__(self):
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport
        if DEBUG_MODE:
            logger.info("UDP server started")

    async def process_udp_message(self, data, addr):
        try:
            message = json.loads(data.decode())
            if DEBUG_MODE:
                logger.info(f"Received UDP message with MAC from {addr}")

            if "nonce" not in message:
                return

            if message["nonce"] in used_nonces:
                return
            used_nonces.add(message["nonce"])

            recipient_id = message.get("recipient_id")
            if recipient_id in active_clients:
                recipient = active_clients[recipient_id]
                if recipient.udp_port:
                    # ارسال از طریق UDP
                    self.transport.sendto(data, (recipient.ip_address, recipient.udp_port))
                    if DEBUG_MODE:
                        logger.info(f"Forwarded UDP message with MAC to {recipient_id} at {recipient.ip_address}:{recipient.udp_port}")
                elif recipient_id in websocket_connections:
                    # ارسال از طریق WebSocket اگر UDP در دسترس نباشد
                    await websocket_connections[recipient_id].send_text(json.dumps({
                        "type": "message",
                        "sender_id": message.get("sender_id"),
                        "encrypted_message": message.get("encrypted_message"),
                        "timestamp": message.get("timestamp"),
                        "dh_public_key": message.get("dh_public_key"),
                        "nonce": message["nonce"]
                    }))
                    if DEBUG_MODE:
                        logger.info(f"Fallback to WebSocket for {recipient_id}")
        except Exception as e:
            logger.error(f"UDP message error: {e}")

    def datagram_received(self, data, addr):
        asyncio.create_task(self.process_udp_message(data, addr))

    def error_received(self, exc):
        logger.error(f"UDP error: {exc}")

async def start_udp_server():
    loop = asyncio.get_running_loop()
    await loop.create_datagram_endpoint(
        lambda: UDPServerProtocol(),
        local_addr=('0.0.0.0', 8001)
    )
    if DEBUG_MODE:
        logger.info("UDP server running on port 8001")

@app.on_event("startup")
async def startup_event():
    if DEBUG_MODE:
        logger.info("Starting Secure Messaging Server...")
    asyncio.create_task(cleanup_inactive_clients())
    asyncio.create_task(cleanup_old_dh_keys_task())
    asyncio.create_task(cleanup_old_sessions_task())
    asyncio.create_task(cleanup_old_file_transfers_task())
    asyncio.create_task(start_udp_server())

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

async def cleanup_old_dh_keys_task():
    """Periodically clean up old DH keys"""
    while True:
        await asyncio.sleep(3600)  # Check every hour
        try:
            db_manager.cleanup_old_dh_keys()
        except Exception as e:
            logger.error(f"Error in cleanup_old_dh_keys_task: {e}")

async def cleanup_old_sessions_task():
    """Periodically clean up old sessions every 24 hours"""
    while True:
        await asyncio.sleep(86400)  # 24 hours in seconds
        try:
            db_manager.cleanup_old_sessions()
        except Exception as e:
            logger.error(f"Error in cleanup_old_sessions_task: {e}")

async def cleanup_old_file_transfers_task():
    """Periodically clean up old file transfers every 24 hours"""
    while True:
        await asyncio.sleep(86400)  # 24 hours in seconds
        try:
            db_manager.cleanup_old_file_transfers()
        except Exception as e:
            logger.error(f"Error in cleanup_old_file_transfers_task: {e}")

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
    )