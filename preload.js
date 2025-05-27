// preload.js - با Auto-Cleanup Events
const { contextBridge, ipcRenderer } = require('electron');

// Expose secure API to renderer
contextBridge.exposeInMainWorld('secureAPI', {
    // Client management
    registerClient: (clientName) => ipcRenderer.invoke('register-client', clientName),
    findClient: (clientId) => ipcRenderer.invoke('find-client', clientId),
    regenerateClientId: () => ipcRenderer.invoke('regenerate-client-id'),
    
    // Messaging
    sendMessage: (messageData) => ipcRenderer.invoke('send-message', messageData),
    getActiveChats: () => ipcRenderer.invoke('get-active-chats'),
    
    // Chat management
    endChat: (clientId) => ipcRenderer.invoke('end-chat', clientId),
    deleteChat: (clientId) => ipcRenderer.invoke('delete-chat', clientId),
    
    // Window controls
    minimizeWindow: () => ipcRenderer.invoke('minimize-window'),
    maximizeWindow: () => ipcRenderer.invoke('maximize-window'),
    closeWindow: () => ipcRenderer.invoke('close-window'),
    
    // Event listeners
    onNewMessage: (callback) => {
        ipcRenderer.on('new-message', (event, data) => callback(data));
    },
    
    onMessageNotification: (callback) => {
        ipcRenderer.on('message-notification', (event, data) => callback(data));
    },
    
    onChatEnded: (callback) => {
        ipcRenderer.on('chat-ended', (event, clientId) => callback(clientId));
    },
    
    onChatDeleted: (callback) => {
        ipcRenderer.on('chat-deleted', (event, clientId) => callback(clientId));
    },
    
    onChatDeletedByPeer: (callback) => {
        ipcRenderer.on('chat-deleted-by-peer', (event, data) => callback(data));
    },
    
    // NEW: Auto-cleanup events
    onChatAutoClean: (callback) => {
        ipcRenderer.on('chat-auto-cleaned', (event, data) => callback(data));
    },
    
    onChatEndedImmediately: (callback) => {
        ipcRenderer.on('chat-ended-immediately', (event, data) => callback(data));
    },
    
    onChatCleanupInactive: (callback) => {
        ipcRenderer.on('chat-cleanup-inactive', (event, data) => callback(data));
    },
    
    // NEW: Remove chat from sidebar
    onRemoveChatFromSidebar: (callback) => {
        ipcRenderer.on('remove-chat-from-sidebar', (event, data) => callback(data));
    },
    
    // File transfer progress events
    onFileSendProgress: (callback) => {
        ipcRenderer.on('file-send-progress', (event, data) => callback(data));
    },
    
    onFileReceiveStart: (callback) => {
        ipcRenderer.on('file-receive-start', (event, data) => callback(data));
    },
    
    onFileReceiveProgress: (callback) => {
        ipcRenderer.on('file-receive-progress', (event, data) => callback(data));
    },
    
    // Remove listeners
    removeAllListeners: (channel) => {
        ipcRenderer.removeAllListeners(channel);
    }
});