import CONFIG from '../utils/config';

class WebSocketService {
    constructor() {
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 3000;
        this.messageQueue = [];
        this.intentionalClose = false; // Flag para evitar reconexión durante logout
        this.listeners = {
            connected: [],
            message: [],
            typing: [],
            online: [],
            offline: [],
            error: [],
            close: []
        };
    }

    /**
     * Conectar al WebSocket
     */
    connect(token) {
        if (!token) {
            console.error('No hay token de autenticación');
            return;
        }

        // Evitar conexiones duplicadas
        if (this.ws && (this.ws.readyState === WebSocket.CONNECTING || this.ws.readyState === WebSocket.OPEN)) {
            console.log('WebSocket ya está conectado o conectando');
            return;
        }

        // Cerrar conexión anterior si existe
        if (this.ws) {
            this.ws.close();
        }

        const wsUrl = `${CONFIG.WS_URL}?token=${token}`;

        try {
            this.ws = new WebSocket(wsUrl);

            this.ws.onopen = this.handleOpen.bind(this);
            this.ws.onmessage = this.handleMessage.bind(this);
            this.ws.onerror = this.handleError.bind(this);
            this.ws.onclose = this.handleClose.bind(this);

        } catch (error) {
            console.error('Error conectando WebSocket:', error);
            this.emit('error', error);
        }
    }

    /**
     * Manejar apertura de conexión
     */
    handleOpen() {
        console.log('WebSocket conectado');
        this.reconnectAttempts = 0;
        this.intentionalClose = false;
        this.flushMessageQueue();
        this.emit('connected');
    }

    /**
     * Manejar mensaje recibido
     */
    handleMessage(event) {
        try {
            const data = JSON.parse(event.data);
            console.log('📨 [WebSocket] Mensaje recibido:', data);

            switch (data.type) {
                case 'connected':
                    console.log('✓ [WebSocket] Conectado al servidor como:', data.username);
                    break;

                case 'new_message':
                    console.log('💬 [WebSocket] Nuevo mensaje de:', data.sender_username);
                    this.emit('message', data);
                    break;

                case 'typing_notification':
                    this.emit('typing', data);
                    break;

                case 'user_online':
                    this.emit('online', data);
                    break;

                case 'user_offline':
                    this.emit('offline', data);
                    break;

                case 'message_sent':
                    console.log('✓ [WebSocket] Mensaje enviado confirmado. ID:', data.message_id);
                    break;

                case 'message_read':
                    console.log('✓ [WebSocket] Mensaje leído:', data.message_id);
                    break;

                case 'online_users':
                    this.emit('online', { users: data.users });
                    break;
                
                case 'error':
                    console.error('❌ [WebSocket] Error del servidor:', data.message);
                    break;

                default:
                    console.log('⚠️ [WebSocket] Tipo de mensaje desconocido:', data.type);
            }
        } catch (error) {
            console.error('❌ [WebSocket] Error procesando mensaje:', error);
        }
    }

    /**
     * Manejar error
     */
    handleError(error) {
        console.error('Error en WebSocket:', error);
        this.emit('error', error);
    }

    /**
     * Manejar cierre de conexión
     */
    handleClose(event) {
        console.group('🔴 [WebSocket] Conexión cerrada');
        console.log('Código:', event.code);
        console.log('Razón:', event.reason || 'Sin razón especificada');
        console.log('¿Cierre limpio?:', event.wasClean);
        console.groupEnd();
        
        this.emit('close');
        this.attemptReconnect();
    }

    /**
     * Intentar reconexión
     */
    attemptReconnect() {
        if (this.intentionalClose) {
            console.log('Cierre intencional, no se reconectará');
            return;
        }

        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            console.log(`Intentando reconectar (${this.reconnectAttempts}/${this.maxReconnectAttempts})...`);

            setTimeout(() => {
                const token = localStorage.getItem(CONFIG.STORAGE_KEYS.ACCESS_TOKEN);
                if (token) {
                    this.connect(token);
                }
            }, this.reconnectDelay);
        } else {
            console.error('Máximo de intentos de reconexión alcanzado');
        }
    }

    /**
     * Enviar mensaje
     */
    send(data) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            console.log('📡 [WebSocket] Enviando mensaje:', data.type);
            this.ws.send(JSON.stringify(data));
            console.log('✓ [WebSocket] Mensaje enviado correctamente');
        } else {
            console.warn('⚠️ [WebSocket] No conectado, mensaje en cola. Estado:', this.ws?.readyState);
            this.messageQueue.push(data);
        }
    }

    /**
     * Enviar mensajes en cola
     */
    flushMessageQueue() {
        while (this.messageQueue.length > 0) {
            const message = this.messageQueue.shift();
            this.send(message);
        }
    }

    /**
     * Suscribirse a eventos
     */
    on(event, callback) {
        if (this.listeners[event]) {
            this.listeners[event].push(callback);
        }
    }

    /**
     * Desuscribirse de eventos
     */
    off(event, callback) {
        if (this.listeners[event]) {
            this.listeners[event] = this.listeners[event].filter(cb => cb !== callback);
        }
    }

    /**
     * Emitir evento
     */
    emit(event, data) {
        if (this.listeners[event]) {
            this.listeners[event].forEach(callback => callback(data));
        }
    }

    /**
     * Enviar notificación de escritura
     */
    sendTyping(recipientId) {
        this.send({
            type: 'typing',
            recipient_id: recipientId
        });
    }

    /**
     * Marcar mensaje como leído
     */
    markAsRead(messageId) {
        this.send({
            type: 'mark_read',
            message_id: messageId
        });
    }

    /**
     * Desconectar
     */
    disconnect() {
        this.intentionalClose = true;
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
        this.reconnectAttempts = 0;
        this.messageQueue = [];
    }
}

// Exportar instancia única
const wsService = new WebSocketService();
export default wsService;
