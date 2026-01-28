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
            close: [],
            group_message: [],
            group_typing: [],
            joined_group: [],
            left_group: [],
            member_joined_group: [],
            member_left_group: []
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

                // === Mensajes de grupo ===
                case 'group_message':
                case 'new_group_message':
                    console.log('✓ [WebSocket] Nuevo mensaje de grupo:', data.group_id);
                    this.emit('group_message', data);
                    break;

                case 'group_message_sent':
                    console.log('✓ [WebSocket] Mensaje de grupo enviado confirmado. ID:', data.message_id);
                    this.emit('group_message', data);
                    break;

                case 'joined_group':
                    console.log('✓ [WebSocket] Te uniste al grupo:', data.group_id);
                    this.emit('joined_group', data);
                    break;

                case 'left_group':
                    console.log('✓ [WebSocket] Saliste del grupo:', data.group_id);
                    this.emit('left_group', data);
                    break;

                case 'group_typing':
                case 'group_typing_notification':
                    console.log('✓ [WebSocket] Usuario escribiendo en grupo:', data.group_id);
                    this.emit('group_typing', data);
                    break;

                case 'member_joined_group':
                    console.log('✓ [WebSocket] Nuevo miembro en grupo:', data.group_id);
                    this.emit('member_joined_group', data);
                    break;

                case 'member_left_group':
                    console.log('✓ [WebSocket] Miembro salió del grupo:', data.group_id);
                    this.emit('member_left_group', data);
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
            console.log(`📝 [WebSocket] Listener registrado para evento '${event}'. Total: ${this.listeners[event].length}`);
        }
    }

    /**
     * Desuscribirse de eventos
     */
    off(event, callback) {
        if (this.listeners[event]) {
            const before = this.listeners[event].length;
            this.listeners[event] = this.listeners[event].filter(cb => cb !== callback);
            const after = this.listeners[event].length;
            console.log(`🗑️ [WebSocket] Listener eliminado para evento '${event}'. Antes: ${before}, Después: ${after}`);
        }
    }

    /**
     * Emitir evento
     */
    emit(event, data) {
        if (this.listeners[event]) {
            console.log(`📢 [WebSocket] Emitiendo evento '${event}' a ${this.listeners[event].length} listener(s)`);
            this.listeners[event].forEach(callback => callback(data));
        } else {
            console.warn(`⚠️ [WebSocket] No hay listeners para el evento '${event}'`);
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

    // ================= MÉTODOS DE GRUPO =================

    /**
     * Unirse a una sala de grupo
     */
    joinGroup(groupId) {
        console.log('📡 [WebSocket] Uniéndose a grupo:', groupId);
        this.send({
            type: 'join_group',
            group_id: groupId
        });
    }

    /**
     * Salir de una sala de grupo
     */
    leaveGroup(groupId) {
        console.log('📡 [WebSocket] Saliendo de grupo:', groupId);
        this.send({
            type: 'leave_group',
            group_id: groupId
        });
    }

    /**
     * Enviar mensaje a grupo
     */
    sendGroupMessage(groupId, encryptedContent, iv, signature) {
        console.log('📡 [WebSocket] Enviando mensaje a grupo:', groupId);
        this.send({
            type: 'group_message',
            group_id: groupId,
            encrypted_data: {
                encrypted_message: encryptedContent,
                iv: iv,
                signature: signature
            }
        });
    }

    /**
     * Enviar notificación de escritura en grupo
     */
    sendGroupTyping(groupId) {
        this.send({
            type: 'group_typing',
            group_id: groupId
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
