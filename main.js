// main.js - با Auto-Cleanup و حذف فوری PD
const { app, BrowserWindow, ipcMain, dialog } = require('electron');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const WebSocket = require('ws');
const axios = require('axios');

// Performance optimization flags
const DEBUG_MODE = process.env.NODE_ENV === 'development';
const log = DEBUG_MODE ? console.log : () => {};
const logError = console.error; // Always log errors
const logInfo = DEBUG_MODE ? console.log : () => {};

class SecureP2PClient {
    constructor(serverUrl = 'https://indust.aiframe.org', cryptoManager, username) {
        this.window = null;
        this.clientId = null;
        this.username = username || null;
        this.serverUrl = serverUrl;
        this.websocket = null;
        this.heartbeatInterval = null;
        this.cryptoManager = cryptoManager || new CryptoManager(serverUrl);
        this.activeChats = new Map();
        this.fileChunks = new Map();
        this.messageBuffers = new Map();
        this.chatActivities = new Map();
        this.cleanupInterval = null;
        this.reconnectAttempts = 0;
        this.isClosing = false;
        this.INACTIVE_TIMEOUT = 10 * 60 * 1000;
        this.CLEANUP_CHECK_INTERVAL = 2 * 60 * 1000;
        this.p2pServer = null;
        this.p2pPort = null;
        this.connections = new Map();
        this.usedNonces = new Map();
        // تنظیمات UDP
        this.udpClient = null;
        this.udpPort = null;
        this.udpHost = this.serverUrl.replace('https://', '').replace('http://', '');
    }

    async initialize() {
        this.createWindow();
        this.setupIPC();
        await this.initializeCrypto(false); // تولید اولیه همه کلیدها
        this.startActivityCleanup();
        this.startDHKeyRefresh(); // اضافه کردن تازه‌سازی کلیدهای DH
    
        // Check if clientId exists, otherwise wait for registration
        if (!this.clientId) {
            logInfo('No clientId found, waiting for registration...');
            // Registration will be handled via IPC 'register-client'
        } else {
            await this.connectToServer();
        }
    }

    startDHKeyRefresh() {
        const refreshDHKeys = async () => {
            try {
                await this.initializeCrypto(true); // فقط کلیدهای DH تازه‌سازی می‌شوند
            } catch (error) {
                logError('Error refreshing DH keys:', error);
            }
        };
    
        // تازه‌سازی هر 30 دقیقه
        setInterval(refreshDHKeys, 30 * 60 * 1000);
    
        // تازه‌سازی در شروع هر چت
        ipcMain.handle('start-new-chat', async (event, recipientId) => {
            await refreshDHKeys();
            this.updateChatActivity(recipientId);
            return { success: true };
        });
    }

    createWindow() {
        this.window = new BrowserWindow({
            width: 1200,
            height: 800,
            minWidth: 800,
            minHeight: 600,
            webPreferences: {
                nodeIntegration: false,
                contextIsolation: true,
                preload: path.join(__dirname, 'preload.js')
            },
            frame: false,
            titleBarStyle: 'hidden',
            backgroundColor: '#0a0a0a',
            icon: path.join(__dirname, 'assets/icon.png')
        });

        this.window.loadFile('renderer/index.html');
        
        // Handle window close event
        this.window.on('close', async (event) => {
            // Prevent immediate close to send PD messages first
            if (!this.isClosing) {
                event.preventDefault();
                this.isClosing = true;
                
                logInfo('Window closing, sending PD to all active chats...');
                
                // Send PD to all active chats
                await this.sendPDToAllActiveChats();
                
                // Now allow window to close
                this.window.destroy();
            }
        });
        
        if (DEBUG_MODE) {
            this.window.webContents.openDevTools();
        }
    }

    async initializeCrypto(refreshDHOnly = false) {
        try {
            if (!refreshDHOnly) {
                // تولید اولیه همه کلیدها
                await this.cryptoManager.generateKeys(); // تولید RSA و ECC
                await this.cryptoManager.generateDHKeys(); // تولید اولیه DH
                logInfo('Crypto keys and DH keys generated successfully');
            } else {
                // فقط تازه‌سازی کلیدهای DH
                await this.cryptoManager.generateDHKeys();
                logInfo('DH keys refreshed successfully');
                if (this.clientId) {
                    // امضای کلید عمومی DH با ECC برای تأیید
                    const keys = await this.cryptoManager.getPublicKeys();
                    const sign = crypto.createSign('SHA256');
                    sign.update(keys.dh);
                    const dhSignature = sign.sign(this.cryptoManager.eccKeyPair.privateKey, 'hex');
    
                    // به‌روزرسانی کلید در سرور از طریق API
                    try {
                        await axios.post(`${this.serverUrl}/update_keys`, {
                            client_id: this.clientId,
                            dh_public_key: keys.dh,
                            dh_signature: dhSignature // امضای کلید DH
                        });
                        logInfo('Updated DH public key on server via API with signature');
                    } catch (error) {
                        logError('Failed to update DH public key on server:', error);
                    }
    
                    // ارسال به WebSocket برای اطلاع‌رسانی به کاربران دیگر
                    if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                        this.websocket.send(JSON.stringify({
                            type: 'update_keys',
                            client_id: this.clientId,
                            dh_public_key: keys.dh,
                            dh_signature: dhSignature
                        }));
                        logInfo('Updated DH public key sent to WebSocket with signature');
                    }
                }
            }
        } catch (error) {
            logError('Error during crypto initialization:', error);
            throw error;
        }
    }

    startActivityCleanup() {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
        }
        
        this.cleanupInterval = setInterval(() => {
            this.checkInactiveChats();
            this.cleanupOldNonces(); // تمیزکاری nonce‌های قدیمی
        }, this.CLEANUP_CHECK_INTERVAL);
        
        logInfo('Activity cleanup timer started');
    }
    
    // متد جدید برای تمیزکاری nonce‌ها
    cleanupOldNonces() {
        const now = Date.now();
        const oneHourAgo = now - (60 * 60 * 1000); // 1 ساعت قبل
        let deletedCount = 0;
    
        // پیمایش روی تمام nonce‌ها در usedNonces
        for (const [nonce, timestamp] of this.usedNonces) {
            if (timestamp < oneHourAgo) {
                this.usedNonces.delete(nonce);
                deletedCount++;
            }
        }
    
        if (deletedCount > 0) {
            logInfo(`Cleaned up ${deletedCount} old nonces`);
        } else {
            logInfo('No old nonces to clean up');
        }
    }
    
    // NEW: Check for inactive chats and clean them up
    checkInactiveChats() {
        const now = Date.now();
        const inactiveChats = [];
        
        for (const [chatId, lastActivity] of this.chatActivities) {
            const timeSinceLastActivity = now - lastActivity;
            
            if (timeSinceLastActivity > this.INACTIVE_TIMEOUT) {
                inactiveChats.push(chatId);
                logInfo(`Chat ${chatId.substring(0, 8)}... marked as inactive (${Math.round(timeSinceLastActivity / 60000)} minutes)`);
            }
        }
        
        // Clean up inactive chats
        for (const chatId of inactiveChats) {
            this.cleanupInactiveChat(chatId);
        }
    }

    // NEW: Clean up an inactive chat
    cleanupInactiveChat(chatId) {
        logInfo(`Cleaning up inactive chat: ${chatId.substring(0, 8)}...`);
        
        // Remove from all tracking maps
        this.activeChats.delete(chatId);
        this.chatActivities.delete(chatId);
        this.fileChunks.delete(chatId); // Also clean up any pending file transfers
        
        // Remove from UI
        this.removeChatFromSidebar(chatId);
        
        // If this was the current active chat, go back to welcome screen
        if (this.currentChat === chatId) {
            this.currentChat = null;
            this.window.webContents.send('chat-cleanup-inactive', { clientId: chatId });
        }
        
        // Notify UI about cleanup
        this.window.webContents.send('chat-auto-cleaned', {
            clientId: chatId,
            reason: 'inactivity'
        });
        
        logInfo(`Chat ${chatId.substring(0, 8)}... cleaned up due to inactivity`);
    }

    // NEW: Update chat activity timestamp
    updateChatActivity(chatId) {
        this.chatActivities.set(chatId, Date.now());
        log(`Updated activity for chat: ${chatId.substring(0, 8)}...`);
    }

    // NEW: Remove chat from sidebar via renderer
    removeChatFromSidebar(clientId) {
        if (!clientId) {
            logError('Cannot remove chat from sidebar: clientId is undefined');
            return;
        }
        
        logInfo('Removing chat from sidebar:', clientId.substring(0, 8));
        
        // Send message to renderer to remove chat from UI
        this.window.webContents.send('remove-chat-from-sidebar', {
            clientId: clientId
        });
    }

    setupIPC() {
        // Register client
        ipcMain.handle('register-client', async (event, clientName) => {
            try {
                logInfo(`Registering client: ${clientName}`);
                this.username = clientName;
                
                const keys = await this.cryptoManager.getPublicKeys();
                
                const response = await axios.post(`${this.serverUrl}/register`, {
                    client_name: clientName,
                    rsa_public_key: keys.rsa,
                    ecc_public_key: keys.ecc,
                    dh_public_key: keys.dh // اضافه کردن کلید عمومی DH
                });
        
                if (response.data.success) {
                    this.clientId = response.data.client_id;
                    logInfo(`Client registered with ID: ${this.clientId}`);
                    
                    setTimeout(async () => {
                        await this.connectToServer();
                    }, 1000);
                    
                    return { success: true, clientId: this.clientId };
                }
                
                return { success: false, error: 'Registration failed' };
            } catch (error) {
                logError('Registration error:', error);
                if (error.response) {
                    logError('Server response:', error.response.data);
                }
                return { success: false, error: error.message };
            }
        });

        // Regenerate client ID
        ipcMain.handle('regenerate-client-id', async (event) => {
            try {
                if (!this.clientId) {
                    return { success: false, error: 'No active client ID to regenerate' };
                }
        
                logInfo(`Regenerating client ID for: ${this.clientId}`);
                
                const clientName = this.username || 'RegeneratedUser';
                const keys = await this.cryptoManager.getPublicKeys();
                
                const response = await axios.post(`${this.serverUrl}/regenerate_id`, {
                    old_client_id: this.clientId,
                    client_name: clientName,
                    rsa_public_key: keys.rsa,
                    ecc_public_key: keys.ecc,
                    dh_public_key: keys.dh // اضافه کردن کلید عمومی DH
                });
        
                if (response.data.success) {
                    const oldClientId = this.clientId;
                    this.clientId = response.data.new_client_id;
                    
                    logInfo(`Client ID regenerated: ${oldClientId} → ${this.clientId}`);
                    
                    await this.disconnectFromServer(oldClientId);
                    
                    setTimeout(async () => {
                        await this.connectToServer();
                    }, 1000);
                    
                    return { 
                        success: true, 
                        newClientId: this.clientId,
                        oldClientId: oldClientId 
                    };
                }
                
                return { success: false, error: 'ID regeneration failed' };
            } catch (error) {
                logError('ID Regeneration error:', error);
                if (error.response) {
                    logError('Server response:', error.response.data);
                }
                return { success: false, error: error.message };
            }
        });

        // Find client
        ipcMain.handle('find-client', async (event, targetClientId) => {
            try {
                const response = await axios.get(`${this.serverUrl}/find_client/${targetClientId}`);
                return response.data;
            } catch (error) {
                logError('Find client error:', error);
                return { success: false, error: error.message };
            }
        });

        // Send message with activity tracking
        ipcMain.handle('send-message', async (event, messageData) => {
            try {
                const { recipientId, message } = messageData;
                
                // Update activity for this chat
                this.updateChatActivity(recipientId);
                
                // Check message size
                const messageSize = Buffer.byteLength(message, 'utf8');
                const isLargeMessage = messageSize > 1024 * 1024; // 1MB threshold
                
                // Check if it's a file
                let isFileMessage = false;
                try {
                    const parsedMessage = JSON.parse(message);
                    if (parsedMessage && parsedMessage.type === 'file') {
                        isFileMessage = true;
                        log(`Sending file: ${parsedMessage.fileName}, Size: ${messageSize} bytes`);
                    }
                } catch (e) {
                    // Regular text message
                }
                
                // Get recipient's public keys
                const recipientInfo = await axios.get(`${this.serverUrl}/find_client/${recipientId}`);
                if (!recipientInfo.data.success) {
                    throw new Error('Recipient not found');
                }

                // Handle large files with chunking
                if (isFileMessage && isLargeMessage) {
                    return await this.sendLargeFile(message, recipientInfo.data.client_info);
                } else {
                    // Regular message sending
                    return await this.sendRegularMessage(message, recipientInfo.data.client_info);
                }
                
            } catch (error) {
                logError('Send message error:', error);
                return { success: false, error: error.message };
            }
        });

        // ENHANCED: End chat with immediate cleanup
        ipcMain.handle('end-chat', async (event, clientId) => {
            try {
                logInfo(`Ending chat with immediate cleanup: ${clientId}`);
                
                // STEP 1: Send PD message to peer
                const result = await this.sendPDMessage(clientId);
                
                // STEP 2: Immediately clean up local chat (don't wait for response)
                this.immediateLocalCleanup(clientId);
                
                return { success: true, cleaned: true };
                
            } catch (error) {
                logError('End chat error:', error);
                return { success: false, error: error.message };
            }
        });

        // Other IPC handlers remain the same...
        ipcMain.handle('get-active-chats', async () => {
            return Array.from(this.activeChats.entries()).map(([clientId, chat]) => ({
                clientId,
                messages: chat.messages,
                status: chat.status
            }));
        });

        ipcMain.handle('delete-chat', async (event, clientId) => {
            if (this.activeChats.has(clientId)) {
                this.activeChats.delete(clientId);
                this.window.webContents.send('chat-deleted', clientId);
            }
        });

        ipcMain.handle('notify-peer-chat-ended', async (event, clientId) => {
            try {
                if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                    this.websocket.send(JSON.stringify({
                        type: 'chat_ended_notification',
                        recipient_id: clientId,
                        sender_id: this.clientId,
                        timestamp: Date.now()
                    }));
                }
            } catch (error) {
                logError('Notify peer chat ended error:', error);
            }
        });

        ipcMain.handle('notify-peer-chat-deleted', async (event, clientId) => {
            try {
                if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                    this.websocket.send(JSON.stringify({
                        type: 'chat_deleted_notification',
                        recipient_id: clientId,
                        sender_id: this.clientId,
                        timestamp: Date.now()
                    }));
                }
            } catch (error) {
                logError('Notify peer chat deleted error:', error);
            }
        });

        // Window controls
        ipcMain.handle('minimize-window', () => {
            this.window.minimize();
        });

        ipcMain.handle('maximize-window', () => {
            if (this.window.isMaximized()) {
                this.window.unmaximize();
            } else {
                this.window.maximize();
            }
        });

        ipcMain.handle('close-window', async () => {
            // Send PD to all active chats before closing
            await this.sendPDToAllActiveChats();
            this.window.close();
        });
    }

    async setupUDP() {
        const dgram = require('dgram');
        this.udpClient = dgram.createSocket('udp4');
    
        this.udpClient.on('listening', () => {
            const address = this.udpClient.address();
            this.udpPort = address.port;
            logInfo(`UDP client listening on ${address.address}:${address.port}`);
        });
    
        this.udpClient.on('message', (msg, rinfo) => {
            try {
                const message = JSON.parse(msg.toString());
                this.handleWebSocketMessage(message); // استفاده از همان متد برای پردازش پیام‌ها
                logInfo(`Received UDP message from ${rinfo.address}:${rinfo.port}`);
            } catch (error) {
                logError('UDP message parse error:', error);
            }
        });
    
        this.udpClient.on('error', (error) => {
            logError('UDP client error:', error);
            this.udpClient.close();
            setTimeout(() => this.setupUDP(), 5000);
        });
    
        this.udpClient.bind();
    }

    // NEW: Send PD to all active chats before exit
    async sendPDToAllActiveChats() {
        if (this.activeChats.size === 0) {
            logInfo('No active chats to send PD messages to');
            return;
        }
    
        logInfo(`Sending PD to ${this.activeChats.size} active chats before exit`);
        
        const pdPromises = [];
        
        for (const [chatClientId] of this.activeChats) {
            logInfo(`Sending exit PD to: ${chatClientId.substring(0, 8)}...`);
            
            const pdPromise = this.sendPDMessage(chatClientId).catch(error => {
                logError(`Failed to send exit PD to ${chatClientId}:`, error);
                // Don't throw, just log and continue
            });
            
            pdPromises.push(pdPromise);
        }
        
        // Send all PD messages with shorter timeout for exit
        try {
            await Promise.race([
                Promise.allSettled(pdPromises),
                new Promise(resolve => setTimeout(resolve, 2000)) // Max 2 seconds wait
            ]);
            logInfo('Exit PD messages sent (or timed out)');
        } catch (error) {
            logError('Error sending exit PD messages:', error);
        }
        
        // Shorter delay for exit
        await new Promise(resolve => setTimeout(resolve, 200));
    }
    
    async sendPDMessage(recipientId) {
        try {
            const zlib = require('zlib');
            // Get recipient's public keys
            const recipientInfo = await axios.get(`${this.serverUrl}/find_client/${recipientId}`);
            if (!recipientInfo.data.success || !recipientInfo.data.client_info) {
                logInfo(`Recipient ${recipientId} not found for PD message - proceeding with local cleanup`);
                return { success: true, message: 'Recipient offline, local cleanup only' };
            }
    
            const { rsa_public_key, ecc_public_key, dh_public_key } = recipientInfo.data.client_info;
    
            // بررسی وجود کلید عمومی DH
            if (!dh_public_key) {
                logInfo(`No DH public key found for recipient ${recipientId} - proceeding with local cleanup`);
                return { success: true, message: 'No DH public key, local cleanup only' };
            }
    
            // تولید nonce با timestamp
            const nonceObj = {
                value: crypto.randomBytes(16).toString('hex'),
                timestamp: Date.now()
            };
            const nonce = nonceObj.value;
            logInfo('Generated nonce for PD:', nonce);
    
            // بسته‌بندی پیام PD با nonce
            const pdMessage = {
                content: 'PD',
                nonce: nonceObj
            };
    
            // فشرده‌سازی پیام PD قبل از رمزنگاری
            const compressedMessage = zlib.deflateSync(JSON.stringify(pdMessage)).toString('base64');
            logInfo(`Compressed PD message size: ${Buffer.byteLength(compressedMessage, 'utf8')} bytes`);
    
            // رمزنگاری پیام PD فشرده‌شده
            const encryptedMessage = await this.cryptoManager.tripleEncrypt(
                compressedMessage,
                rsa_public_key,
                ecc_public_key,
                dh_public_key
            );
    
            if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                this.websocket.send(JSON.stringify({
                    type: 'message',
                    sender_id: this.clientId,
                    recipient_id: recipientId,
                    encrypted_message: encryptedMessage,
                    timestamp: Date.now(),
                    nonce: nonce
                }));
                logInfo(`PD message with MAC sent successfully to: ${recipientId} with nonce: ${nonce}`);
            } else {
                logInfo('WebSocket not connected, proceeding with local cleanup');
                return { success: true, message: 'WebSocket not connected, local cleanup only' };
            }
    
            // ذخیره nonce با timestamp در usedNonces
            this.usedNonces.set(nonce, nonceObj.timestamp);
    
            return { success: true };
        } catch (error) {
            logError('Error sending PD message with MAC:', error);
            return { success: true, message: 'PD send failed but local cleanup will proceed' };
        }
    }

    // NEW: Immediate local cleanup after sending PD
    immediateLocalCleanup(clientId) {
        logInfo(`Performing immediate local cleanup for: ${clientId}`);
        
        // Remove from all tracking
        this.activeChats.delete(clientId);
        this.chatActivities.delete(clientId);
        this.fileChunks.delete(clientId);
        
        // Remove from UI
        this.removeChatFromSidebar(clientId);
        
        // Reset current chat if needed
        if (this.currentChat === clientId) {
            this.currentChat = null;
        }
        
        // Notify renderer about immediate cleanup
        this.window.webContents.send('chat-ended-immediately', {
            clientId: clientId,
            reason: 'user_ended'
        });
        
        logInfo(`Immediate cleanup completed for: ${clientId}`);
    }

    async sendLargeFile(fileMessage, recipientInfo) {
        try {
            const zlib = require('zlib');
            const parsedFile = JSON.parse(fileMessage);
            const fileData = parsedFile.fileData;
            const chunkSize = 512 * 1024;
            const totalChunks = Math.ceil(fileData.length / chunkSize);
            const fileId = crypto.randomUUID();
  
            log(`Sending large file in ${totalChunks} chunks`);
            this.updateChatActivity(recipientInfo.client_id);
  
            let lastSentChunk = -1;
            if (this.fileChunks.has(fileId)) {
                const existingTransfer = this.fileChunks.get(fileId);
                lastSentChunk = existingTransfer.lastSentChunk || -1;
                logInfo(`Resuming file transfer for fileId ${fileId} from chunk ${lastSentChunk + 1}`);
            }
  
            const headerMessage = {
                type: 'file_header',
                fileId: fileId,
                fileName: parsedFile.fileName,
                fileSize: parsedFile.fileSize,
                fileType: parsedFile.fileType,
                totalChunks: totalChunks,
                timestamp: parsedFile.timestamp,
                lastSentChunk: lastSentChunk
            };
  
            const compressedHeader = zlib.deflateSync(JSON.stringify(headerMessage)).toString('base64');
            logInfo(`Compressed header size: ${Buffer.byteLength(compressedHeader, 'utf8')} bytes`);
  
            const encryptedHeader = await this.cryptoManager.tripleEncrypt(
                compressedHeader,
                recipientInfo.rsa_public_key,
                recipientInfo.ecc_public_key,
                recipientInfo.dh_public_key
            );
  
            const nonceObj = {
                value: crypto.randomBytes(16).toString('hex'),
                timestamp: Date.now()
            };
            const nonce = nonceObj.value;
            logInfo('Generated nonce for file header:', nonce);
  
            const headerToSend = JSON.stringify({
                type: 'message',
                sender_id: this.clientId,
                recipient_id: recipientInfo.client_id,
                encrypted_message: encryptedHeader,
                timestamp: Date.now(),
                nonce: nonce
            });
  
            if (this.udpClient && recipientInfo.udp_port) {
                this.udpClient.send(headerToSend, recipientInfo.udp_port, this.udpHost, (error) => {
                    if (error) {
                        logError('UDP send error for header:', error);
                        if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                            this.websocket.send(headerToSend);
                        }
                    }
                });
            } else if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                this.websocket.send(headerToSend);
            } else {
                throw new Error('Neither UDP nor WebSocket is available');
            }
  
            this.fileChunks.set(fileId, {
                fileId: fileId,
                totalChunks: totalChunks,
                lastSentChunk: lastSentChunk,
                chunks: new Array(totalChunks).fill(null),
                recipientId: recipientInfo.client_id
            });
  
            for (let i = lastSentChunk + 1; i < totalChunks; i++) {
                const start = i * chunkSize;
                const end = Math.min(start + chunkSize, fileData.length);
                const chunk = fileData.slice(start, end);
  
                const chunkMessage = {
                    type: 'file_chunk',
                    fileId: fileId,
                    chunkIndex: i,
                    chunkData: chunk,
                    isLastChunk: i === totalChunks - 1
                };
  
                const compressedChunk = zlib.deflateSync(JSON.stringify(chunkMessage)).toString('base64');
                logInfo(`Compressed chunk ${i} size: ${Buffer.byteLength(compressedChunk, 'utf8')} bytes`);
  
                const encryptedChunk = await this.cryptoManager.tripleEncrypt(
                    compressedChunk,
                    recipientInfo.rsa_public_key,
                    recipientInfo.ecc_public_key,
                    recipientInfo.dh_public_key
                );
  
                const chunkNonceObj = {
                    value: crypto.randomBytes(16).toString('hex'),
                    timestamp: Date.now()
                };
                const chunkNonce = chunkNonceObj.value;
                logInfo(`Generated nonce for chunk ${i}:`, chunkNonce);
  
                const chunkToSend = JSON.stringify({
                    type: 'message',
                    sender_id: this.clientId,
                    recipient_id: recipientInfo.client_id,
                    encrypted_message: encryptedChunk,
                    timestamp: Date.now(),
                    nonce: chunkNonce
                });
  
                if (this.udpClient && recipientInfo.udp_port) {
                    this.udpClient.send(chunkToSend, recipientInfo.udp_port, this.udpHost, (error) => {
                        if (error) {
                            logError('UDP send error for chunk:', error);
                            if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                                this.websocket.send(chunkToSend);
                            }
                        }
                    });
                } else if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                    this.websocket.send(chunkToSend);
                } else {
                    throw new Error('Neither UDP nor WebSocket is available');
                }
  
                const transfer = this.fileChunks.get(fileId);
                transfer.lastSentChunk = i;
                this.usedNonces.set(chunkNonce, chunkNonceObj.timestamp);
                this.fileChunks.set(fileId, transfer);
  
                if (i < totalChunks - 1) {
                    await new Promise(resolve => setTimeout(resolve, 50)); // افزایش تأخیر به 50 میلی‌ثانیه
                }
  
                this.window.webContents.send('file-send-progress', {
                    progress: ((i + 1) / totalChunks) * 100,
                    fileId: fileId
                });
            }
  
            this.storeMessage(recipientInfo.client_id, fileMessage, 'sent');
            log(`Large file with MAC sent successfully: ${parsedFile.fileName}`);
            return { success: true };
        } catch (error) {
            logError('Large file send with MAC error:', error);
            return { success: false, error: error.message, fileId: fileId };
        }
    }

    async sendRegularMessage(message, recipientInfo) {
        try {
            const zlib = require('zlib');
            this.updateChatActivity(recipientInfo.client_id);
            await this.cryptoManager.generateDHKeys();
            const keys = await this.cryptoManager.getPublicKeys();
    
            const updatedRecipientInfo = await axios.get(`${this.serverUrl}/find_client/${recipientInfo.client_id}`);
            if (!updatedRecipientInfo.data.success) {
                throw new Error('Failed to fetch updated recipient info');
            }
            const { rsa_public_key, ecc_public_key, dh_public_key } = updatedRecipientInfo.data.client_info;
    
            const nonceObj = {
                value: crypto.randomBytes(16).toString('hex'),
                timestamp: Date.now()
            };
            const nonce = nonceObj.value;
            logInfo('Generated nonce:', nonce);
    
            const messageWithNonce = {
                content: message,
                nonce: nonceObj
            };
    
            const compressedMessage = zlib.deflateSync(JSON.stringify(messageWithNonce)).toString('base64');
            logInfo(`Compressed message size: ${Buffer.byteLength(compressedMessage, 'utf8')} bytes`);
    
            const encryptedMessage = await this.cryptoManager.tripleEncrypt(
                compressedMessage,
                rsa_public_key,
                ecc_public_key,
                dh_public_key
            );
    
            const messageToSend = JSON.stringify({
                type: 'message',
                sender_id: this.clientId,
                recipient_id: recipientInfo.client_id,
                encrypted_message: encryptedMessage,
                timestamp: Date.now(),
                dh_public_key: keys.dh,
                nonce: nonce
            });
    
            // ارسال از طریق UDP اگر ممکن باشد، در غیر این صورت از WebSocket
            if (this.udpClient && updatedRecipientInfo.data.client_info.udp_port) {
                this.udpClient.send(messageToSend, updatedRecipientInfo.data.client_info.udp_port, this.udpHost, (error) => {
                    if (error) {
                        logError('UDP send error:', error);
                        if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                            this.websocket.send(messageToSend);
                            logInfo('Fallback to WebSocket for message sending');
                        }
                    } else {
                        logInfo(`Message sent via UDP to ${recipientInfo.client_id}`);
                    }
                });
            } else if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                this.websocket.send(messageToSend);
                logInfo('Message sent via WebSocket (UDP not available)');
            } else {
                throw new Error('Neither UDP nor WebSocket is available');
            }
    
            this.usedNonces.set(nonce, nonceObj.timestamp);
    
            this.storeMessage(recipientInfo.client_id, message, 'sent');
            logInfo(`Regular message with MAC sent to ${recipientInfo.client_id} with new DH key and nonce`);
            return { success: true };
        } catch (error) {
            logError('Send regular message with MAC error:', error);
            throw error;
        }
    }

    startCleanupInterval() {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
        }
        this.cleanupInterval = setInterval(() => {
            const now = Date.now();
            for (const [chatId, lastActivity] of this.chatActivities) {
                if (now - lastActivity > this.INACTIVE_TIMEOUT) {
                    logInfo(`Cleaning up inactive chat: ${chatId.substring(0, 8)}...`);
                    this.activeChats.delete(chatId);
                    this.fileChunks.delete(chatId);
                    this.messageBuffers.delete(chatId);
                    this.chatActivities.delete(chatId);
                }
            }
        }, this.CLEANUP_CHECK_INTERVAL); // بررسی هر 2 دقیقه
        logInfo('Cleanup interval started');
    }

    stopCleanupInterval() {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
            this.cleanupInterval = null;
            logInfo('Cleanup interval stopped');
        }
    }

    stopHeartbeat() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
            logInfo('Heartbeat stopped');
        }
    }

    async connectToServer() {
        try {
            if (!this.clientId) {
                logError('Cannot connect to server: clientId is null');
                return;
            }
            const localIP = await this.getLocalIP();
            logInfo(`Local IP detected: ${localIP}`);
            const response = await axios.post(`${this.serverUrl}/connect`, null, {
                params: { client_id: this.clientId, ip_address: localIP, port: 0, udp_port: this.udpPort }
            });
            if (response.data.success) {
                logInfo('Successfully connected to server');
                const wsUrl = this.serverUrl.replace('http://', 'wss://').replace('https://', 'wss://') + `/ws/${this.clientId}`;
                logInfo(`Attempting WebSocket connection to: ${wsUrl}`);
                this.websocket = new WebSocket(wsUrl);
                this.websocket.on('open', () => {
                    logInfo('WebSocket connected successfully');
                    this.websocket.send(JSON.stringify({ type: 'register', client_id: this.clientId }));
                    this.startHeartbeat();
                    this.startCleanupInterval();
                });
                this.websocket.on('message', async (data) => {
                    try {
                        const message = JSON.parse(data.toString());
                        await this.handleWebSocketMessage(message);
                    } catch (error) {
                        logError('WebSocket message parse error:', error);
                    }
                });
                this.websocket.on('close', () => {
                    logInfo('WebSocket disconnected, scheduling reconnect...');
                    this.stopHeartbeat();
                    this.stopCleanupInterval();
                    if (!this.isClosing) {
                        this.reconnectWebSocket();
                    }
                });
                this.websocket.on('error', (error) => {
                    logError('WebSocket error:', error);
                    this.stopHeartbeat();
                    this.stopCleanupInterval();
                    if (this.websocket) this.websocket.close();
                });
  
                // راه‌اندازی UDP
                await this.setupUDP();
            } else {
                throw new Error('Server connection failed: ' + (response.data.message || 'Unknown error'));
            }
        } catch (error) {
            logError('Connect to server error:', error);
            if (this.reconnectAttempts < 3 && !this.isClosing) {
                this.reconnectAttempts++;
                logInfo(`Reconnect attempt ${this.reconnectAttempts}...`);
                setTimeout(() => this.connectToServer(), 5000 * this.reconnectAttempts);
            } else {
                logError('Max reconnect attempts reached or client is closing');
            }
        }
    }

    async disconnectFromServer(clientId = null) {
        try {
            const targetClientId = clientId || this.clientId;
            if (!targetClientId) return { success: true };
            logInfo(`Disconnecting client: ${targetClientId}`);
            this.isClosing = true;
            this.stopHeartbeat();
            this.stopCleanupInterval();
            if (this.websocket) {
                try { if (this.websocket.readyState === WebSocket.OPEN) this.websocket.close(); }
                catch (error) { logError('Error closing WebSocket:', error); }
                this.websocket = null;
            }
            if (this.p2pServer) {
                try { this.p2pServer.close(); }
                catch (error) { logError('Error closing P2P server:', error); }
                this.p2pServer = null; this.p2pPort = null;
            }
            try {
                const response = await axios.post(`${this.serverUrl}/disconnect`, null, {
                    params: { client_id: targetClientId }, timeout: 5000
                });
                logInfo('Server disconnect response received');
            } catch (error) { logError('Error notifying server about disconnect:', error); }
            this.connections.clear(); this.messageBuffers.clear(); this.chatActivities.clear();
            this.isClosing = false;
            return { success: true };
        } catch (error) {
            logError('Disconnect error:', error);
            this.isClosing = false;
            return { success: false, error: error.message };
        }
    }

    // NEW: Handle received PD message
    handlePDReceived(senderId) {
        logInfo(`Handling PD received from: ${senderId}`);
        
        // ارسال تأییدیه PD به فرستنده
        if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
            const nonceObj = {
                value: crypto.randomBytes(16).toString('hex'),
                timestamp: Date.now()
            };
            const nonce = nonceObj.value;
            logInfo('Generated nonce for PD acknowledgment:', nonce);
    
            // بررسی senderId قبل از ارسال
            if (!senderId) {
                logError('Cannot send pd_ack: senderId is undefined');
                return;
            }
    
            this.websocket.send(JSON.stringify({
                type: 'pd_ack',
                sender_id: this.clientId,
                recipient_id: senderId,
                timestamp: Date.now(),
                nonce: nonce
            }));
            this.usedNonces.set(nonce, nonceObj.timestamp);
        }
        
        // Remove chat completely
        this.activeChats.delete(senderId);
        this.chatActivities.delete(senderId);
        this.fileChunks.delete(senderId);
        
        // Notify UI
        this.window.webContents.send('chat-deleted-by-peer', {
            clientId: senderId
        });
        
        logInfo(`Chat cleaned up after receiving PD from: ${senderId}`);
    }

    // Handle file header
    handleFileHeader(header, senderId) {
        log(`Receiving file: ${header.fileName} in ${header.totalChunks} chunks`);
    
        this.updateChatActivity(senderId);
    
        // بررسی وجود انتقال قبلی
        let receivedChunks = 0;
        let chunks = new Array(header.totalChunks).fill(null);
        if (this.fileChunks.has(header.fileId)) {
            const existingTransfer = this.fileChunks.get(header.fileId);
            chunks = existingTransfer.chunks;
            receivedChunks = existingTransfer.receivedChunks;
            logInfo(`Resuming file transfer for fileId ${header.fileId}, already received ${receivedChunks} chunks`);
        }
    
        this.fileChunks.set(header.fileId, {
            header: header,
            chunks: chunks,
            receivedChunks: receivedChunks,
            senderId: senderId
        });
    
        // اگر تکه‌هایی از قبل دریافت نشده‌اند، درخواست ادامه انتقال
        if (receivedChunks < header.totalChunks && header.lastSentChunk >= 0) {
            this.requestMissingChunks(header.fileId, senderId, receivedChunks);
        }
    
        this.window.webContents.send('file-receive-start', {
            fileId: header.fileId,
            fileName: header.fileName,
            fileSize: header.fileSize,
            senderId: senderId
        });
    }

    // Handle file chunks
    async handleFileChunk(chunk, senderId, timestamp) {
        const fileTransfer = this.fileChunks.get(chunk.fileId);
        if (!fileTransfer) {
            logError('Received chunk for unknown file:', chunk.fileId);
            return;
        }
        
        // Update activity
        this.updateChatActivity(senderId);
        
        // Store chunk
        fileTransfer.chunks[chunk.chunkIndex] = chunk.chunkData;
        fileTransfer.receivedChunks++;
        
        // Update progress
        const progress = (fileTransfer.receivedChunks / fileTransfer.header.totalChunks) * 100;
        this.window.webContents.send('file-receive-progress', {
            fileId: chunk.fileId,
            progress: progress
        });
        
        // Check if all chunks received or if this is a resumption
        if (chunk.isLastChunk || fileTransfer.receivedChunks === fileTransfer.header.totalChunks) {
            log(`All chunks received for file: ${fileTransfer.header.fileName}`);
            
            // Reconstruct file
            const reconstructedData = fileTransfer.chunks.join('');
            
            const completeFileMessage = {
                type: 'file',
                fileName: fileTransfer.header.fileName,
                fileSize: fileTransfer.header.fileSize,
                fileType: fileTransfer.header.fileType,
                fileData: reconstructedData,
                timestamp: fileTransfer.header.timestamp
            };
            
            // Store and display
            this.storeMessage(senderId, JSON.stringify(completeFileMessage), 'received');
            
            this.window.webContents.send('new-message', {
                senderId: senderId,
                message: JSON.stringify(completeFileMessage),
                timestamp: timestamp
            });
            
            // Cleanup
            this.fileChunks.delete(chunk.fileId);
            
            log(`File reconstruction complete: ${fileTransfer.header.fileName}`);
        } else if (fileTransfer.receivedChunks < fileTransfer.header.totalChunks) {
            // Check for missing chunks and request them if needed
            const missingChunks = [];
            for (let i = 0; i < fileTransfer.header.totalChunks; i++) {
                if (!fileTransfer.chunks[i]) {
                    missingChunks.push(i);
                }
            }
            if (missingChunks.length > 0) {
                await this.requestMissingChunks(fileTransfer.header.fileId, senderId, fileTransfer.receivedChunks);
                logInfo(`Requested missing chunks ${missingChunks} for fileId ${fileTransfer.header.fileId}`);
            }
        }
    }

async requestMissingChunks(fileId, senderId, receivedChunks) {
      let attempts = 0;
      const maxAttempts = 3;

      while (attempts < maxAttempts) {
          try {
              if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                  const nonceObj = {
                      value: crypto.randomBytes(16).toString('hex'),
                      timestamp: Date.now()
                  };
                  const nonce = nonceObj.value;

                  this.websocket.send(JSON.stringify({
                      type: 'request_missing_chunks',
                      fileId: fileId,
                      sender_id: this.clientId,
                      recipient_id: senderId,
                      received_chunks: receivedChunks,
                      timestamp: Date.now(),
                      nonce: nonce
                  }));

                  this.usedNonces.set(nonce, nonceObj.timestamp);
                  logInfo(`Requested missing chunks for fileId ${fileId} from ${senderId}`);
                  break; // موفقیت‌آمیز بود، از حلقه خارج شو
              } else {
                  throw new Error('WebSocket not connected');
              }
          } catch (error) {
              attempts++;
              logError(`Attempt ${attempts} to request missing chunks failed: ${error.message}`);
              if (attempts === maxAttempts) {
                  this.window.webContents.send('error', {
                      message: `Failed to request missing chunks for fileId ${fileId} after ${maxAttempts} attempts`
                  });
                  return;
              }
              await new Promise(resolve => setTimeout(resolve, 2000 * attempts)); // انتظار 2، 4، 6 ثانیه
          }
      }
  }

    // Helper function
    tryParseJSON(str) {
        try {
            return JSON.parse(str);
        } catch (e) {
            return null;
        }
    }

    storeMessage(clientId, message, type) {
        if (!this.activeChats.has(clientId)) {
            this.activeChats.set(clientId, {
                messages: [],
                status: 'active'
            });
        }
        
        this.activeChats.get(clientId).messages.push({
            message,
            type,
            timestamp: Date.now()
        });
        
        // Update activity when storing messages
        this.updateChatActivity(clientId);
    }

    handleWebSocketMessage(message) {
        switch (message.type) {
            case 'register_ack':
                logInfo('Registered with server');
                break;
            case 'message':
                this.handleIncomingMessage(message);
                break;
            case 'message_ack':
                logInfo('Message sent successfully');
                break;
            case 'pd_ack':
                if (!message.recipient_id) {
                    logError('Received pd_ack message without recipient_id:', message);
                    return;
                }
                this.handlePDAck(message.recipient_id);
                break;
            case 'request_missing_chunks':
                this.handleMissingChunksRequest(message);
                break;
            case 'error':
                logError('Server error:', message.message);
                this.window.webContents.send('error', { message: message.message });
                break;
            default:
                log(`Unknown message type: ${message.type}`);
        }
    }

    async handleMissingChunksRequest(message) {
        try {
            const { fileId, recipient_id, received_chunks } = message;
            const fileTransfer = this.fileChunks.get(fileId);
            if (!fileTransfer) {
                logError(`File transfer not found for fileId ${fileId}`);
                return;
            }
    
            const totalChunks = fileTransfer.totalChunks;
            const recipientInfo = await axios.get(`${this.serverUrl}/find_client/${recipient_id}`);
            if (!recipientInfo.data.success) {
                throw new Error('Recipient not found');
            }
    
            logInfo(`Resending chunks for fileId ${fileId} from chunk ${received_chunks}`);
    
            for (let i = received_chunks; i < totalChunks; i++) {
                const chunk = fileTransfer.chunks[i];
                if (!chunk) continue;
    
                const chunkMessage = {
                    type: 'file_chunk',
                    fileId: fileId,
                    chunkIndex: i,
                    chunkData: chunk,
                    isLastChunk: i === totalChunks - 1
                };
    
                const compressedChunk = zlib.deflateSync(JSON.stringify(chunkMessage)).toString('base64');
                const encryptedChunk = await this.cryptoManager.tripleEncrypt(
                    compressedChunk,
                    recipientInfo.data.client_info.rsa_public_key,
                    recipientInfo.data.client_info.ecc_public_key,
                    recipientInfo.data.client_info.dh_public_key
                );
    
                if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                    this.websocket.send(JSON.stringify({
                        type: 'message',
                        sender_id: this.clientId,
                        recipient_id: recipient_id,
                        encrypted_message: encryptedChunk,
                        timestamp: Date.now()
                    }));
                }
    
                if (i < totalChunks - 1) {
                    await new Promise(resolve => setTimeout(resolve, 10));
                }
            }
    
            logInfo(`Finished resending chunks for fileId ${fileId}`);
        } catch (error) {
            logError('Error handling missing chunks request:', error);
        }
    }
    
    handlePDAck(recipientId) {
        logInfo(`Received PD acknowledgment from: ${recipientId}`);
        this.activeChats.delete(recipientId);
        this.chatActivities.delete(recipientId);
        this.fileChunks.delete(recipientId);
        this.removeChatFromSidebar(recipientId);
        this.window.webContents.send('chat-deleted-by-peer', { clientId: recipientId });
    }

    async handleIncomingMessage(message) {
        try {
            if (!message.nonce) {
                throw new Error('Message nonce missing');
            }
    
            // بررسی nonce با استفاده از Map
            if (this.usedNonces.has(message.nonce)) {
                throw new Error('Replay attack detected: nonce already used');
            }
    
            logInfo('Sender ID received:', message.sender_id);
    
            const decryptedMessage = await this.cryptoManager.tripleDecrypt(message.encrypted_message, message.sender_id);
            this.updateChatActivity(message.sender_id);
    
            // تلاش برای تحلیل پیام رمزگشایی‌شده به‌عنوان جیسون
            let messageObj = this.tryParseJSON(decryptedMessage);
            if (!messageObj) {
                // اگر تحلیل به‌عنوان جیسون ناموفق بود، آن را به‌عنوان متن خام در نظر بگیریم
                messageObj = { content: decryptedMessage, nonce: { value: message.nonce, timestamp: Date.now() } };
            }
    
            // اضافه کردن nonce به usedNonces با timestamp
            this.usedNonces.set(message.nonce, Date.now());
    
            if (messageObj.content === 'PD') {
                logInfo('Received PD signal from:', message.sender_id);
                await this.handlePDReceived(message.sender_id);
                return;
            }
    
            // بررسی نوع پیام (فایل یا متن)
            if (messageObj.type === 'file_header') {
                return this.handleFileHeader(messageObj, message.sender_id);
            } else if (messageObj.type === 'file_chunk') {
                return this.handleFileChunk(messageObj, message.sender_id, message.timestamp);
            }
    
            // ذخیره پیام متنی معمولی
            this.storeMessage(message.sender_id, messageObj.content, 'received');
            this.window.webContents.send('new-message', {
                senderId: message.sender_id,
                message: messageObj.content,
                timestamp: message.timestamp
            });
            logInfo(`Message received and decrypted successfully from ${message.sender_id}`);
        } catch (error) {
            logError('Message decryption error:', error);
            this.window.webContents.send('error', { message: 'Failed to decrypt message' });
        }
    }

    async reconnectWebSocket() {
        if (!this.clientId) return;
        try {
            logInfo('Attempting to reconnect WebSocket...');
            const wsUrl = this.serverUrl.replace('http://', 'wss://').replace('https://', 'wss://') + `/ws/${this.clientId}`;
            this.websocket = new WebSocket(wsUrl);
            this.websocket.on('open', () => {
                logInfo('WebSocket reconnected successfully');
                this.websocket.send(JSON.stringify({ type: 'register', client_id: this.clientId }));
                this.startHeartbeat();
            });
            this.websocket.on('message', async (data) => {
                try {
                    const message = JSON.parse(data.toString());
                    await this.handleWebSocketMessage(message);
                } catch (error) {
                    logError('WebSocket message parse error:', error);
                }
            });
            this.websocket.on('close', () => {
                logInfo('WebSocket disconnected, scheduling reconnect...');
                this.stopHeartbeat();
                if (!this.isClosing) setTimeout(() => this.reconnectWebSocket(), 5000);
            });
            this.websocket.on('error', (error) => {
                logError('WebSocket reconnection error:', error);
                this.stopHeartbeat();
                if (this.websocket) this.websocket.close();
            });
        } catch (error) {
            logError('WebSocket reconnection failed:', error);
            if (!this.isClosing) setTimeout(() => this.reconnectWebSocket(), 5000);
        }
    }


    startHeartbeat() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
        }
    
        this.heartbeatInterval = setInterval(() => {
            if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                this.websocket.send(JSON.stringify({
                    type: 'heartbeat',
                    timestamp: Date.now()
                }));
                logInfo('Heartbeat sent');
            } else {
                logInfo('WebSocket not open, stopping heartbeat');
                this.stopHeartbeat();
            }
        }, 30000); // ارسال heartbeat هر 30 ثانیه
    }

    async getLocalIP() {
        try {
            const { networkInterfaces } = require('os');
            const nets = networkInterfaces();
            
            for (const name of Object.keys(nets)) {
                for (const net of nets[name]) {
                    if (net.family === 'IPv4' && !net.internal) {
                        log(`Found local IP: ${net.address} on interface ${name}`);
                        return net.address;
                    }
                }
            }
            
            log('No external IP found, using localhost');
            return '127.0.0.1';
        } catch (error) {
            logError('Error getting local IP:', error);
            return '127.0.0.1';
        }
    }
}

class CryptoManager {
    constructor(serverUrl) {
        this.serverUrl = serverUrl; // اضافه کردن serverUrl
        this.rsaKeyPair = null;
        this.eccKeyPair = null;
        this.dhKeyPair = null;
    }
    async generateKeys() {
        try {
            // Generate RSA key pair
            this.rsaKeyPair = crypto.generateKeyPairSync('rsa', {
                modulusLength: 1024,
                publicKeyEncoding: {
                    type: 'spki',
                    format: 'pem'
                },
                privateKeyEncoding: {
                    type: 'pkcs8',
                    format: 'pem'
                }
            });

            // Generate ECC key pair
            this.eccKeyPair = crypto.generateKeyPairSync('ec', {
                namedCurve: 'prime256v1',
                publicKeyEncoding: {
                    type: 'spki',
                    format: 'pem'
                },
                privateKeyEncoding: {
                    type: 'pkcs8',
                    format: 'pem'
                }
            });
            
            logInfo('Crypto keys generated successfully');
        } catch (error) {
            logError('Error generating keys:', error);
            throw error;
        }
    }

    async generateDHKeys() {
        try {
            const dh = crypto.createDiffieHellmanGroup('modp14'); // گروه 2048 بیتی RFC 7919
            dh.generateKeys(); // تولید کلیدهای خصوصی و عمومی
            const rawPublicKey = dh.getPublicKey('hex');
            // استفاده از HKDF برای بهینه‌سازی کلید
            const hkdf = crypto.createHmac('sha256', 'dh_key_derivation_salt');
            hkdf.update(Buffer.from(rawPublicKey, 'hex'));
            const derivedPublicKey = hkdf.digest().slice(0, 32); // 32 بایت (256 بیت) برای استفاده امن
            this.dhKeyPair = {
                dhInstance: dh,
                publicKey: derivedPublicKey.toString('hex') // کلید عمومی بهینه‌شده
            };
            logInfo('Generated DH public key length:', this.dhKeyPair.publicKey.length);
            logInfo('Generated DH public key (derived):', this.dhKeyPair.publicKey);
            logInfo('Diffie-Hellman keys generated with HKDF optimization');
        } catch (error) {
            logError('Error generating DH keys:', error);
            throw error;
        }
    }
    
    async computeSharedSecret(recipientDHPublicKey) {
        try {
            // بررسی وجود کلید عمومی گیرنده
            if (!recipientDHPublicKey) {
                throw new Error('Recipient DH public key is undefined');
            }
    
            // استفاده از نمونه DH ذخیره‌شده
            const dh = this.dhKeyPair.dhInstance;
            logInfo('Recipient DH Public Key:', recipientDHPublicKey);
            logInfo('Recipient DH Public Key Length:', recipientDHPublicKey.length);
            const rawSharedSecret = dh.computeSecret(Buffer.from(recipientDHPublicKey, 'hex'), 'hex', 'hex');
            logInfo('Raw Shared Secret Length:', rawSharedSecret.length);
            logInfo('Raw Shared Secret:', rawSharedSecret);
    
            // بهینه‌سازی کلید با HKDF برای امنیت بیشتر
            const hkdf = crypto.createHmac('sha256', 'session_key_salt_' + Date.now()); // Salt پویا با timestamp
            hkdf.update(Buffer.from(rawSharedSecret, 'hex'));
            const sessionKey = hkdf.digest().slice(0, 32); // 32 بایت (256 بیت) برای AES-256
            
            logInfo('Derived Session Key Length:', sessionKey.length);
            logInfo('Computed and derived DH shared secret successfully');
            return sessionKey; // بازگرداندن بافر 32 بایت
        } catch (error) {
            logError('Error computing DH shared secret:', error);
            throw error;
        }
    }

    async getPublicKeys() {
        try {
            return {
                rsa: this.rsaKeyPair.publicKey,
                ecc: this.eccKeyPair.publicKey,
                dh: this.dhKeyPair.publicKey // کلید DH در فرمت hex
            };
        } catch (error) {
            logError('Error getting public keys:', error);
            throw error;
        }
    }

    async tripleEncrypt(message, recipientRSAKey, recipientECCKey, recipientDHPublicKey) {
        try {
            const messageSize = Buffer.byteLength(message, 'utf8');
            if (messageSize > 1024 * 1024) {
                log(`Encrypting large message: ${messageSize} bytes`);
            }
    
            // محاسبه کلید مشترک DH
            const sessionKey = await this.computeSharedSecret(recipientDHPublicKey);
            const aesKey = sessionKey;
            const iv = crypto.randomBytes(16);
    
            // رمزنگاری پیام با AES-256-GCM
            const aesCipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
            let aesEncrypted = aesCipher.update(message, 'utf8', 'hex');
            aesEncrypted += aesCipher.final('hex');
            const aesTag = aesCipher.getAuthTag();
    
            // رمزنگاری کلید جلسه‌ای با RSA
            const rsaEncryptedKey = crypto.publicEncrypt({
                key: recipientRSAKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            }, sessionKey);
    
            // تولید امضای ECC
            const sign = crypto.createSign('SHA256');
            sign.update(aesEncrypted);
            const signature = sign.sign(this.eccKeyPair.privateKey, 'hex');
    
            // تولید MAC با استفاده از کلید مشترک DH (sessionKey)
            const macKey = sessionKey; // کلید مشترک برای HMAC
            const mac = crypto.createHmac('sha256', macKey);
            mac.update(aesEncrypted);
            const macValue = mac.digest('hex');
    
            const result = {
                aesEncrypted,
                aesTag: aesTag.toString('hex'),
                rsaEncryptedKey: rsaEncryptedKey.toString('hex'),
                signature,
                iv: iv.toString('hex'),
                dhPublicKey: this.dhKeyPair.publicKey,
                mac: macValue // اضافه کردن MAC به خروجی
            };
    
            logInfo('Triple encryption with MAC completed successfully');
            return result;
        } catch (error) {
            logError('Triple encryption with MAC error:', error);
            throw error;
        }
    }
    
    async tripleDecrypt(encryptedData, senderId) {
        try {
            const zlib = require('zlib');
    
            // دریافت کلید عمومی ECC فرستنده از سرور
            const senderInfo = await axios.get(`${this.serverUrl}/find_client/${senderId}`);
            if (!senderInfo.data.success) {
                throw new Error('Sender not found');
            }
            const senderECCPublicKey = senderInfo.data.client_info.ecc_public_key;
    
            // محاسبه کلید جلسه‌ای با کلید عمومی DH فرستنده
            logInfo('Received DH Public Key:', encryptedData.dhPublicKey);
            logInfo('Received DH Public Key Length:', encryptedData.dhPublicKey.length);
            const computedSessionKey = await this.computeSharedSecret(encryptedData.dhPublicKey);
            logInfo('Computed Session Key Length:', computedSessionKey.length);
            logInfo('Computed Session Key:', computedSessionKey.toString('hex'));
    
            // رمزگشایی کلید جلسه‌ای با RSA
            const sessionKey = crypto.privateDecrypt({
                key: this.rsaKeyPair.privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            }, Buffer.from(encryptedData.rsaEncryptedKey, 'hex'));
            logInfo('Decrypted RSA Session Key Length:', sessionKey.length);
            logInfo('Decrypted RSA Session Key:', sessionKey.toString('hex'));
    
            // تأیید اولیه کلیدهای جلسه‌ای
            if (computedSessionKey.toString('hex') !== sessionKey.toString('hex')) {
                // logError('Session key mismatch');
            }
    
            // تأیید MAC قبل از ادامه
            const macKey = sessionKey; // کلید مشترک برای HMAC
            const computedMac = crypto.createHmac('sha256', macKey);
            computedMac.update(encryptedData.aesEncrypted);
            const computedMacValue = computedMac.digest('hex');
    
            if (computedMacValue !== encryptedData.mac) {
                throw new Error('MAC verification failed: message tampered');
            }
            logInfo('MAC verified successfully');
    
            // تأیید امضای ECC
            const verify = crypto.createVerify('SHA256');
            verify.update(encryptedData.aesEncrypted);
            const isSignatureValid = verify.verify(senderECCPublicKey, encryptedData.signature, 'hex');
            if (!isSignatureValid) {
                throw new Error('ECC signature verification failed: message tampered');
            }
            logInfo('ECC signature verified successfully');
    
            // رمزگشایی پیام با AES-256-GCM
            const aesDecipher = crypto.createDecipheriv('aes-256-gcm', sessionKey, Buffer.from(encryptedData.iv, 'hex'));
            aesDecipher.setAuthTag(Buffer.from(encryptedData.aesTag, 'hex'));
    
            let decrypted = aesDecipher.update(encryptedData.aesEncrypted, 'hex', 'utf8');
            decrypted += aesDecipher.final('utf8');
    
            // از حالت فشرده خارج کردن پیام
            const decompressed = zlib.inflateSync(Buffer.from(decrypted, 'base64')).toString();
            logInfo('Message decompressed successfully');
    
            logInfo('Triple decryption with MAC verification completed successfully');
            return decompressed;
        } catch (error) {
            logError('Triple decryption with MAC verification error:', error);
            throw error;
        }
    }
}

// Application lifecycle
const client = new SecureP2PClient();

// GPU process optimization
app.commandLine.appendSwitch('disable-gpu-process-crash-limit');
app.commandLine.appendSwitch('disable-gpu-sandbox');
app.commandLine.appendSwitch('disable-gpu');

app.whenReady().then(() => {
    client.initialize();
});

app.on('window-all-closed', async () => {
    if (client.heartbeatInterval) {
        clearInterval(client.heartbeatInterval);
    }
    
    if (client.cleanupInterval) {
        clearInterval(client.cleanupInterval);
    }
    
    if (client.p2pServer) {
        client.p2pServer.close();
    }
    
    await client.disconnectFromServer();
    
    if (process.platform !== 'darwin') {
        app.quit();
    }
});

app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
        client.initialize();
    }
});

// Handle process termination signals
process.on('SIGINT', async () => {
    logInfo('Received SIGINT, sending PD to all active chats...');
    await client.sendPDToAllActiveChats();
    process.exit(0);
});

process.on('SIGTERM', async () => {
    logInfo('Received SIGTERM, sending PD to all active chats...');
    await client.sendPDToAllActiveChats();
    process.exit(0);
});

// Handle unexpected crashes
process.on('uncaughtException', async (error) => {
    logError('Uncaught exception:', error);
    await client.sendPDToAllActiveChats();
    process.exit(1);
});

process.on('unhandledRejection', async (reason, promise) => {
    logError('Unhandled rejection at:', promise, 'reason:', reason);
    await client.sendPDToAllActiveChats();
    process.exit(1);
});