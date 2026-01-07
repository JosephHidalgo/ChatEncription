// Gestor de WebSocket para chat en tiempo real
class WebSocketManager {
    constructor() {
        this.ws = null;
        this.reconnectAttempts = 0;
        this.maxReconnectAttempts = 5;
        this.reconnectDelay = 3000;
        this.messageQueue = [];
        this.handlers = {
            connected: [],
            message: [],
            typing: [],
            online: [],
            offline: [],
            error: []
        };
    }

    /**
     * Conectar al WebSocket
     */
    connect() {
        const token = localStorage.getItem(CONFIG.STORAGE_KEYS.ACCESS_TOKEN);
        
        if (!token) {
            console.error('No hay token de autenticación');
            return;
        }

        const wsUrl = `${CONFIG.WS_URL}?token=${token}`;
        
        try {
            this.ws = new WebSocket(wsUrl);
            
            this.ws.onopen = this.onOpen.bind(this);
            this.ws.onmessage = this.onMessage.bind(this);
            this.ws.onerror = this.onError.bind(this);
            this.ws.onclose = this.onClose.bind(this);
            
        } catch (error) {
            console.error('Error conectando WebSocket:', error);
            this.emit('error', error);
        }
    }

    /**
     * Evento: Conexión abierta
     */
    onOpen(event) {
        DEBUG.ws('WebSocket CONECTADO');
        this.reconnectAttempts = 0;
        
        // Enviar mensajes en cola
        this.flushMessageQueue();
        
        this.emit('connected');
    }

    /**
     * Evento: Mensaje recibido
     */
    onMessage(event) {
        try {
            const data = JSON.parse(event.data);
            DEBUG.ws('Mensaje WS recibido', data);
            
            switch (data.type) {
                case 'connected':
                    DEBUG.success('Conectado al servidor');
                    showToast('success', 'Conectado', 'Conectado al chat seguro');
                    break;
                    
                case 'new_message':
                    this.handleNewMessage(data);
                    break;
                    
                case 'typing_notification':
                    this.emit('typing', data);
                    break;
                    
                case 'user_online':
                    this.emit('online', data);
                    updateUserStatus(data.user_id, true);
                    break;
                    
                case 'user_offline':
                    this.emit('offline', data);
                    updateUserStatus(data.user_id, false);
                    break;
                    
                case 'message_sent':
                    console.log('Mensaje enviado correctamente:', data.message_id);
                    break;
                    
                case 'message_read':
                    console.log('Mensaje leído:', data.message_id);
                    break;
                    
                case 'online_users':
                    this.emit('online', { users: data.users });
                    break;
                    
                case 'error':
                    showToast('error', 'Error', data.message);
                    break;
                    
                default:
                    console.log('Tipo de mensaje desconocido:', data.type);
            }
        } catch (error) {
            console.error('Error procesando mensaje:', error);
        }
    }

    /**
     * Maneja un nuevo mensaje recibido
     */
    async handleNewMessage(data) {
        try {
            DEBUG.ws('Nuevo mensaje de usuario: ' + data.sender_id);
            DEBUG.crypto('Datos cifrados recibidos', data.encrypted_data);
            
            // Obtener mi ID de usuario
            let myUserId = parseInt(localStorage.getItem(CONFIG.STORAGE_KEYS.USER_ID));
            
            // Si no hay USER_ID guardado, obtenerlo del usuario actual
            if (isNaN(myUserId) && currentUser) {
                myUserId = currentUser.id;
                localStorage.setItem(CONFIG.STORAGE_KEYS.USER_ID, myUserId.toString());
                DEBUG.info('USER_ID recuperado de currentUser: ' + myUserId);
            }
            
            DEBUG.info('Mi user ID: ' + myUserId);
            DEBUG.info('Sender ID (del mensaje WS): ' + data.sender_id);
            
            // IMPORTANTE: Ignorar mensajes propios (ya se mostraron al enviar)
            if (data.sender_id === myUserId) {
                DEBUG.info('Ignorando mensaje propio (ya mostrado al enviar)');
                return;
            }
            
            // Descifrar el mensaje
            const privateKey = localStorage.getItem(CONFIG.STORAGE_KEYS.PRIVATE_KEY);
            
            // Obtener clave pública del emisor (aunque no se usa en versión simplificada)
            DEBUG.info('Obteniendo clave pública del emisor...');
            const senderKey = await API.getUserPublicKey(data.sender_id);
            
            // Asegurar que el envelope tenga los IDs correctos
            const envelope = data.encrypted_data;
            envelope.sender_id = data.sender_id;  // Usar el sender_id del mensaje WS
            envelope.recipient_id = myUserId;      // Yo soy el receptor
            
            // Descifrar (versión simplificada con clave de conversación)
            DEBUG.crypto('Descifrando mensaje...');
            const decrypted = await CryptoModule.openSecureEnvelope(
                envelope,
                privateKey,
                senderKey.public_key_rsa,
                myUserId
            );
            
            DEBUG.success('Mensaje descifrado: ' + decrypted.message);
            
            // Emitir evento con mensaje descifrado
            // El handler en app.js se encargará de mostrarlo
            this.emit('message', {
                id: data.message_id,
                sender_id: data.sender_id,
                sender_username: data.sender_username,
                content: decrypted.message,
                timestamp: data.timestamp,
                signatureValid: decrypted.signatureValid
            });
            
        } catch (error) {
            DEBUG.error('Error descifrando: ' + error.message);
            DEBUG.error('Stack: ' + error.stack);
            
            // Mostrar mensaje de error más descriptivo
            showToast('error', 'Error de descifrado', 
                'No se pudo descifrar el mensaje. Verifica que ambos dispositivos estén usando el mismo token de sesión.');
            
            // Mostrar el error en la interfaz
            displayMessage({
                message: '⚠️ [Error: No se pudo descifrar este mensaje]',
                sender_id: data.sender_id,
                sender_username: data.sender_username,
                timestamp: data.timestamp,
                isError: true
            });
        }
    }

    /**
     * Evento: Error
     */
    onError(error) {
        console.error('❌ WebSocket error:', error);
        this.emit('error', error);
    }

    /**
     * Evento: Conexión cerrada
     */
    onClose(event) {
        DEBUG.warn(`WebSocket CERRADO - Código: ${event.code}, Razón: ${event.reason || 'Sin razón'}`);
        
        // Intentar reconectar
        if (this.reconnectAttempts < this.maxReconnectAttempts) {
            this.reconnectAttempts++;
            DEBUG.info(`Reintentando conexión (${this.reconnectAttempts}/${this.maxReconnectAttempts})...`);
            
            setTimeout(() => {
                this.connect();
            }, this.reconnectDelay);
        } else {
            DEBUG.error('No se pudo reconectar al servidor');
            showToast('error', 'Desconectado', 'No se pudo reconectar al servidor');
        }
    }

    /**
     * Enviar mensaje
     */
    send(data) {
        if (this.ws && this.ws.readyState === WebSocket.OPEN) {
            this.ws.send(JSON.stringify(data));
            DEBUG.ws('Datos enviados por WS', data);
        } else {
            DEBUG.warn('WebSocket NO conectado, agregando a cola');
            this.messageQueue.push(data);
        }
    }

    /**
     * Enviar mensaje de chat
     */
    async sendChatMessage(recipientId, message) {
        try {
            DEBUG.info('Preparando envío a usuario: ' + recipientId);
            DEBUG.info('Mensaje: ' + message);
            
            // Obtener mi ID de usuario
            const myUserId = parseInt(localStorage.getItem(CONFIG.STORAGE_KEYS.USER_ID));
            DEBUG.info('Mi user ID: ' + myUserId);
            
            // Obtener clave pública del destinatario
            DEBUG.info('Obteniendo clave pública del destinatario...');
            const recipientKey = await API.getUserPublicKey(recipientId);
            DEBUG.success('Clave pública del destinatario obtenida');
            
            // Obtener MI clave pública (para cifrar copia para mí mismo)
            DEBUG.info('Obteniendo MI clave pública...');
            const myKey = await API.getUserPublicKey(myUserId);
            DEBUG.success('Mi clave pública obtenida');
            
            // Crear sobre cifrado con los IDs de usuario
            // Se cifra la clave AES tanto para el destinatario como para mí (emisor)
            DEBUG.crypto('Creando sobre cifrado (dual encryption)...');
            const envelope = await CryptoModule.createSecureEnvelope(
                message,
                recipientKey.public_key_rsa,  // Clave pública del destinatario
                myUserId,                      // Sender ID
                recipientId,                   // Recipient ID  
                myKey.public_key_rsa           // MI clave pública (para mi copia)
            );
            
            DEBUG.crypto('Sobre cifrado creado', envelope);
            
            // Añadir nonce para prevenir replay attacks
            envelope.nonce = CryptoModule.generateNonce();
            
            // Enviar por WebSocket
            DEBUG.ws('Enviando por WebSocket...');
            this.send({
                type: 'message',
                recipient_id: recipientId,
                encrypted_data: envelope
            });
            
            DEBUG.success('Mensaje enviado correctamente');
            return true;
        } catch (error) {
            DEBUG.error('Error enviando mensaje: ' + error.message);
            DEBUG.error('Stack: ' + error.stack);
            throw error;
        }
    }

    /**
     * Enviar notificación de escritura
     */
    sendTypingNotification(recipientId, isTyping) {
        this.send({
            type: 'typing',
            recipient_id: recipientId,
            is_typing: isTyping
        });
    }

    /**
     * Enviar confirmación de lectura
     */
    sendReadReceipt(messageId) {
        this.send({
            type: 'read_receipt',
            message_id: messageId
        });
    }

    /**
     * Solicitar usuarios en línea
     */
    requestOnlineUsers() {
        this.send({
            type: 'get_online_users'
        });
    }

    /**
     * Enviar mensajes en cola
     */
    flushMessageQueue() {
        while (this.messageQueue.length > 0) {
            const msg = this.messageQueue.shift();
            this.send(msg);
        }
    }

    /**
     * Registrar manejador de eventos
     */
    on(event, handler) {
        if (this.handlers[event]) {
            this.handlers[event].push(handler);
        }
    }

    /**
     * Emitir evento
     */
    emit(event, data) {
        if (this.handlers[event]) {
            this.handlers[event].forEach(handler => handler(data));
        }
    }

    /**
     * Desconectar
     */
    disconnect() {
        if (this.ws) {
            this.ws.close();
            this.ws = null;
        }
    }
}

// La instancia se crea en app.js cuando el usuario inicia sesión
