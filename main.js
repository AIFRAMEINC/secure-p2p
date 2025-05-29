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
    constructor() {
        this.window = null;
        this.clientId = null;
        this.username = null;
        this.serverUrl = 'https://indust.aiframe.org';
        this.websocket = null;
        this.heartbeatInterval = null;
        this.cryptoManager = new CryptoManager();
        this.activeChats = new Map();
        this.fileChunks = new Map();
        this.messageBuffers = new Map();
        this.chatActivities = new Map();
        this.cleanupInterval = null;
        this.INACTIVE_TIMEOUT = 10 * 60 * 1000;
        this.CLEANUP_CHECK_INTERVAL = 2 * 60 * 1000;
        this.isClosing = false;
    }

    async initialize() {
        this.createWindow();
        this.setupIPC();
        await this.initializeCrypto();
        this.startActivityCleanup();
    
        // Check if clientId exists, otherwise wait for registration
        if (!this.clientId) {
            logInfo('No clientId found, waiting for registration...');
            // Registration will be handled via IPC 'register-client'
        } else {
            await this.connectToServer();
        }
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

    async initializeCrypto() {
        await this.cryptoManager.generateKeys();
        logInfo('Crypto keys generated successfully');
    }

    // NEW: Start auto-cleanup timer
    startActivityCleanup() {
        if (this.cleanupInterval) {
            clearInterval(this.cleanupInterval);
        }
        
        this.cleanupInterval = setInterval(() => {
            this.checkInactiveChats();
        }, this.CLEANUP_CHECK_INTERVAL);
        
        logInfo('Activity cleanup timer started');
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
                    ecc_public_key: keys.ecc
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
                    ecc_public_key: keys.ecc
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
            // Get recipient's public keys
            const recipientInfo = await axios.get(`${this.serverUrl}/find_client/${recipientId}`);
            if (!recipientInfo.data.success) {
                logInfo(`Recipient ${recipientId} not found for PD message - proceeding with local cleanup`);
                return { success: true, message: 'Recipient offline, local cleanup only' };
            }
    
            // Encrypt and send PD message
            const encryptedMessage = await this.cryptoManager.tripleEncrypt(
                'PD',
                recipientInfo.data.client_info.rsa_public_key,
                recipientInfo.data.client_info.ecc_public_key
            );
    
            if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                this.websocket.send(JSON.stringify({
                    type: 'message',
                    sender_id: this.clientId,
                    recipient_id: recipientId,
                    encrypted_message: encryptedMessage,
                    timestamp: Date.now()
                }));
            } else {
                logInfo('WebSocket not connected, proceeding with local cleanup');
                return { success: true, message: 'WebSocket not connected, local cleanup only' };
            }
    
            logInfo(`PD message sent successfully to: ${recipientId}`);
            return { success: true };
        } catch (error) {
            logError('Error sending PD message:', error);
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
            const parsedFile = JSON.parse(fileMessage);
            const fileData = parsedFile.fileData;
            const chunkSize = 512 * 1024; // 512KB chunks
            const totalChunks = Math.ceil(fileData.length / chunkSize);
            const fileId = crypto.randomUUID();
    
            log(`Sending large file in ${totalChunks} chunks`);
            this.updateChatActivity(recipientInfo.client_id);
    
            // Send file header first
            const headerMessage = {
                type: 'file_header',
                fileId: fileId,
                fileName: parsedFile.fileName,
                fileSize: parsedFile.fileSize,
                fileType: parsedFile.fileType,
                totalChunks: totalChunks,
                timestamp: parsedFile.timestamp
            };
    
            const encryptedHeader = await this.cryptoManager.tripleEncrypt(
                JSON.stringify(headerMessage),
                recipientInfo.rsa_public_key,
                recipientInfo.ecc_public_key
            );
    
            if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                this.websocket.send(JSON.stringify({
                    type: 'message',
                    sender_id: this.clientId,
                    recipient_id: recipientInfo.client_id,
                    encrypted_message: encryptedHeader,
                    timestamp: Date.now()
                }));
            } else {
                throw new Error('WebSocket not connected');
            }
    
            // Send chunks with delay
            for (let i = 0; i < totalChunks; i++) {
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
    
                const encryptedChunk = await this.cryptoManager.tripleEncrypt(
                    JSON.stringify(chunkMessage),
                    recipientInfo.rsa_public_key,
                    recipientInfo.ecc_public_key
                );
    
                if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                    this.websocket.send(JSON.stringify({
                        type: 'message',
                        sender_id: this.clientId,
                        recipient_id: recipientInfo.client_id,
                        encrypted_message: encryptedChunk,
                        timestamp: Date.now()
                    }));
                } else {
                    throw new Error('WebSocket not connected');
                }
    
                if (i < totalChunks - 1) {
                    await new Promise(resolve => setTimeout(resolve, 50));
                }
    
                this.window.webContents.send('file-send-progress', {
                    progress: ((i + 1) / totalChunks) * 100
                });
            }
    
            this.storeMessage(recipientInfo.client_id, fileMessage, 'sent');
            log(`Large file sent successfully: ${parsedFile.fileName}`);
            return { success: true };
        } catch (error) {
            logError('Large file send error:', error);
            return { success: false, error: error.message };
        }
    }

    async sendRegularMessage(message, recipientInfo) {
        try {
            // Update activity
            this.updateChatActivity(recipientInfo.client_id);
    
            const encryptedMessage = await this.cryptoManager.tripleEncrypt(
                message,
                recipientInfo.rsa_public_key,
                recipientInfo.ecc_public_key
            );
    
            if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                this.websocket.send(JSON.stringify({
                    type: 'message',
                    sender_id: this.clientId,
                    recipient_id: recipientInfo.client_id,
                    encrypted_message: encryptedMessage,
                    timestamp: Date.now()
                }));
            } else {
                throw new Error('WebSocket not connected');
            }
    
            this.storeMessage(recipientInfo.client_id, message, 'sent');
            return { success: true };
        } catch (error) {
            logError('Send regular message error:', error);
            throw error;
        }
    }

    async connectToServer() {
        try {
            if (!this.clientId) {
                logError('Cannot connect to server: clientId is null');
                return;
            }
    
            const localIP = await this.getLocalIP();
            const response = await axios.post(`${this.serverUrl}/connect`, null, {
                params: {
                    client_id: this.clientId,
                    ip_address: localIP,
                    port: 0
                }
            });
    
            if (response.data.success) {
                logInfo('Successfully connected to server');
                
                const wsUrl = this.serverUrl.replace('https://', 'wss://') + `/ws/${this.clientId}`;
                logInfo(`Attempting WebSocket connection to: ${wsUrl}`);
                
                this.websocket = new WebSocket(wsUrl);
                
                this.websocket.on('open', () => {
                    logInfo('WebSocket connected successfully');
                    this.websocket.send(JSON.stringify({
                        type: 'register',
                        client_id: this.clientId
                    }));
                    this.startHeartbeat();
                });
    
                this.websocket.on('message', (data) => {
                    try {
                        const message = JSON.parse(data);
                        this.handleWebSocketMessage(message);
                    } catch (error) {
                        logError('WebSocket message parse error:', error);
                    }
                });
    
                this.websocket.on('close', () => {
                    logInfo('WebSocket disconnected, reconnecting...');
                    setTimeout(() => this.reconnectWebSocket(), 5000);
                });
    
                this.websocket.on('error', (error) => {
                    logError('WebSocket error:', error);
                });
            }
        } catch (error) {
            logError('Connect to server error:', error);
        }
    }

    async disconnectFromServer(clientId = null) {
        try {
            const targetClientId = clientId || this.clientId;
            
            if (!targetClientId) {
                return { success: true };
            }

            log(`Disconnecting client: ${targetClientId}`);

            // Stop cleanup timer
            if (this.cleanupInterval) {
                clearInterval(this.cleanupInterval);
                this.cleanupInterval = null;
            }

            if (this.heartbeatInterval) {
                clearInterval(this.heartbeatInterval);
                this.heartbeatInterval = null;
            }

            if (this.websocket) {
                try {
                    if (this.websocket.readyState === WebSocket.OPEN) {
                        this.websocket.close();
                    }
                } catch (error) {
                    logError('Error closing WebSocket:', error);
                }
                this.websocket = null;
            }

            if (this.p2pServer) {
                try {
                    this.p2pServer.close();
                } catch (error) {
                    logError('Error closing P2P server:', error);
                }
                this.p2pServer = null;
                this.p2pPort = null;
            }

            try {
                const response = await axios.post(`${this.serverUrl}/disconnect`, null, {
                    params: {
                        client_id: targetClientId
                    },
                    timeout: 5000
                });
                
                log('Server disconnect response received');
            } catch (error) {
                logError('Error notifying server about disconnect:', error);
            }

            this.connections.clear();
            this.messageBuffers.clear();
            this.chatActivities.clear(); // Clear activity tracking
            return { success: true };

        } catch (error) {
            logError('Disconnect error:', error);
            return { success: false, error: error.message };
        }
    }



    // NEW: Handle received PD message
    handlePDReceived(senderId) {
        logInfo(`Handling PD received from: ${senderId}`);
        
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
        
        // Update activity
        this.updateChatActivity(senderId);
        
        this.fileChunks.set(header.fileId, {
            header: header,
            chunks: new Array(header.totalChunks),
            receivedChunks: 0,
            senderId: senderId
        });
        
        // Notify UI about incoming file
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
        
        // Check if all chunks received
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
            case 'error':
                logError('Server error:', message.message);
                this.window.webContents.send('error', { message: message.message });
                break;
            default:
                log(`Unknown message type: ${message.type}`); // Replaced logWarn with log
        }
    }

    async handleIncomingMessage(message) {
        try {
            const decryptedMessage = await this.cryptoManager.tripleDecrypt(message.encrypted_message);
            this.updateChatActivity(message.sender_id);
    
            if (decryptedMessage === 'PD') {
                logInfo('Received PD signal from:', message.sender_id);
                this.handlePDReceived(message.sender_id);
                return;
            }
    
            const messageObj = this.tryParseJSON(decryptedMessage);
    
            if (messageObj && messageObj.type === 'file_header') {
                return this.handleFileHeader(messageObj, message.sender_id);
            }
    
            if (messageObj && messageObj.type === 'file_chunk') {
                return this.handleFileChunk(messageObj, message.sender_id, message.timestamp);
            }
    
            this.storeMessage(message.sender_id, decryptedMessage, 'received');
            this.window.webContents.send('new-message', {
                senderId: message.sender_id,
                message: decryptedMessage,
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
            const wsUrl = this.serverUrl.replace('https://', 'wss://') + `/ws/${this.clientId}`;
    
            this.websocket = new WebSocket(wsUrl);
    
            this.websocket.on('open', () => {
                logInfo('WebSocket reconnected successfully');
                this.websocket.send(JSON.stringify({
                    type: 'register',
                    client_id: this.clientId
                }));
                this.startHeartbeat();
            });
    
            this.websocket.on('message', (data) => {
                try {
                    const message = JSON.parse(data);
                    this.handleWebSocketMessage(message);
                } catch (error) {
                    logError('WebSocket message parse error:', error);
                }
            });
    
            this.websocket.on('close', () => {
                logInfo('WebSocket disconnected, scheduling reconnect...');
                setTimeout(() => this.reconnectWebSocket(), 5000);
            });
    
            this.websocket.on('error', (error) => {
                logError('WebSocket reconnection error:', error);
            });
        } catch (error) {
            logError('WebSocket reconnection failed:', error);
            setTimeout(() => this.reconnectWebSocket(), 5000);
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
            }
        }, 30000); // Every 30 seconds
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
    constructor() {
        this.rsaKeyPair = null;
        this.eccKeyPair = null;
    }

    async generateKeys() {
        try {
            // Generate RSA key pair
            this.rsaKeyPair = crypto.generateKeyPairSync('rsa', {
                modulusLength: 2048,
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

    async getPublicKeys() {
        return {
            rsa: this.rsaKeyPair.publicKey,
            ecc: this.eccKeyPair.publicKey
        };
    }

    async tripleEncrypt(message, recipientRSAKey, recipientECCKey) {
        try {
            // Optimized for large messages
            const messageSize = Buffer.byteLength(message, 'utf8');
            if (messageSize > 1024 * 1024) { // > 1MB
                log(`Encrypting large message: ${messageSize} bytes`);
            }
            
            // Step 1: Generate AES session key and IV
            const aesKey = crypto.randomBytes(32);
            const iv = crypto.randomBytes(16);

            // Step 2: Encrypt message with AES-256-GCM
            const aesCipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
            let aesEncrypted = aesCipher.update(message, 'utf8', 'hex');
            aesEncrypted += aesCipher.final('hex');
            const aesTag = aesCipher.getAuthTag();

            // Step 3: Encrypt AES key with RSA
            const rsaEncryptedKey = crypto.publicEncrypt({
                key: recipientRSAKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            }, aesKey);

            // Step 4: Sign with ECC
            const sign = crypto.createSign('SHA256');
            sign.update(aesEncrypted);
            const signature = sign.sign(this.eccKeyPair.privateKey, 'hex');

            const result = {
                aesEncrypted,
                aesTag: aesTag.toString('hex'),
                rsaEncryptedKey: rsaEncryptedKey.toString('hex'),
                signature,
                iv: iv.toString('hex')
            };
            
            return result;
        } catch (error) {
            logError('Triple encryption error:', error);
            throw error;
        }
    }

    async tripleDecrypt(encryptedData) {
        try {
            // Step 1: Decrypt AES key with RSA
            const aesKey = crypto.privateDecrypt({
                key: this.rsaKeyPair.privateKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: 'sha256'
            }, Buffer.from(encryptedData.rsaEncryptedKey, 'hex'));

            // Step 2: Decrypt message with AES-256-GCM
            const aesDecipher = crypto.createDecipheriv('aes-256-gcm', aesKey, Buffer.from(encryptedData.iv, 'hex'));
            aesDecipher.setAuthTag(Buffer.from(encryptedData.aesTag, 'hex'));
            
            let decrypted = aesDecipher.update(encryptedData.aesEncrypted, 'hex', 'utf8');
            decrypted += aesDecipher.final('utf8');

            return decrypted;
        } catch (error) {
            logError('Triple decryption error:', error);
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