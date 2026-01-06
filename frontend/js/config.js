// Configuración de la aplicación
// NOTA: Para acceso en red local, cambiar localhost por la IP del servidor
const CONFIG = {
    // Detecta automáticamente si está en localhost o red local
    API_URL: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' 
        ? 'http://localhost:8000' 
        : `http://${window.location.hostname}:8000`,
    
    WS_URL: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? 'ws://localhost:8000/ws/chat'
        : `ws://${window.location.hostname}:8000/ws/chat`,
    
    APP_NAME: 'Chat Seguro',
    VERSION: '1.0.0',
    
    // Configuración de criptografía
    RSA_KEY_SIZE: 2048,
    AES_KEY_SIZE: 256,
    
    // Timeouts
    TYPING_TIMEOUT: 1000,
    MESSAGE_RETRY: 3,
    
    // Almacenamiento local
    STORAGE_KEYS: {
        ACCESS_TOKEN: 'access_token',
        REFRESH_TOKEN: 'refresh_token',
        USER_DATA: 'user_data',
        PRIVATE_KEY: 'private_key',
        PUBLIC_KEY: 'public_key'
    }
};

// Sistema de depuración visual
const DEBUG = {
    enabled: true,
    maxLogs: 50,
    
    log(type, message, data = null) {
        if (!this.enabled) return;
        
        const timestamp = new Date().toLocaleTimeString();
        const colors = {
            'info': '#0af',
            'success': '#0f0',
            'error': '#f00',
            'warn': '#ff0',
            'ws': '#f0f',
            'crypto': '#0ff'
        };
        
        const color = colors[type] || '#fff';
        const icon = {
            'info': 'ℹ️',
            'success': '✅',
            'error': '❌',
            'warn': '⚠️',
            'ws': '🔌',
            'crypto': '🔐'
        }[type] || '📝';
        
        // Log en consola
        console.log(`[${type.toUpperCase()}] ${message}`, data || '');
        
        // Log en panel visual
        const debugLog = document.getElementById('debug-log');
        if (debugLog) {
            const entry = document.createElement('div');
            entry.style.borderBottom = '1px solid #333';
            entry.style.padding = '3px 0';
            entry.style.color = color;
            
            let html = `<span style="color:#888">[${timestamp}]</span> ${icon} ${message}`;
            if (data) {
                const dataStr = typeof data === 'object' ? JSON.stringify(data, null, 0) : data;
                html += `<br><span style="color:#888;margin-left:20px">${dataStr.substring(0, 200)}${dataStr.length > 200 ? '...' : ''}</span>`;
            }
            entry.innerHTML = html;
            
            debugLog.insertBefore(entry, debugLog.firstChild);
            
            // Limitar cantidad de logs
            while (debugLog.children.length > this.maxLogs) {
                debugLog.removeChild(debugLog.lastChild);
            }
        }
    },
    
    info(msg, data) { this.log('info', msg, data); },
    success(msg, data) { this.log('success', msg, data); },
    error(msg, data) { this.log('error', msg, data); },
    warn(msg, data) { this.log('warn', msg, data); },
    ws(msg, data) { this.log('ws', msg, data); },
    crypto(msg, data) { this.log('crypto', msg, data); }
};
