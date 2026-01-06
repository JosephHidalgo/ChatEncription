// Módulo de criptografía para el cliente
// Soporta tanto Web Crypto API (HTTPS) como fallback para HTTP
// v9 - Clave basada en IDs de usuario

const CryptoModule = {
    // Detectar si Web Crypto API está disponible
    isSecureContext: !!(window.crypto && window.crypto.subtle),
    
    // CONFIGURACIÓN DE CIFRADO:
    // - true:  Usa XOR (compatible HTTP + HTTPS, menos seguro)
    // - false: Usa AES-256-CBC (requiere HTTPS o localhost en AMBOS dispositivos)
    forceXorForCompatibility: false,  // Cambiado a false para usar AES
    
    /**
     * Genera un par de claves RSA (simulado - el servidor las genera)
     * En el cliente, solo se almacenan
     */
    async generateKeyPair() {
        // En la implementación real, las claves RSA se generan en el servidor
        // y la clave privada se descarga una sola vez
        console.log('Generando par de claves RSA...');
        return {
            privateKey: null,
            publicKey: null
        };
    },

    /**
     * Genera una clave AES-256 aleatoria
     */
    generateAESKey() {
        // Generar 32 bytes aleatorios (256 bits)
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return this.arrayBufferToBase64(array);
    },

    /**
     * Implementación simple de SHA-256 para contextos no seguros (HTTP)
     * NOTA: Usar solo para desarrollo, en producción usar HTTPS
     */
    async sha256Fallback(message) {
        // Implementación simple de hash para desarrollo
        // En producción, SIEMPRE usar HTTPS para tener crypto.subtle
        let hash = 0;
        const str = typeof message === 'string' ? message : new TextDecoder().decode(message);
        
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        
        // Expandir a 32 bytes para simular SHA-256
        const result = new Uint8Array(32);
        const hashStr = Math.abs(hash).toString(16).padStart(8, '0');
        for (let i = 0; i < 32; i++) {
            result[i] = parseInt(hashStr.substring((i * 2) % hashStr.length, (i * 2) % hashStr.length + 2) || '00', 16) ^ (i * 7);
        }
        
        return result.buffer;
    },

    /**
     * Genera una clave AES determinista basada en los IDs de usuario de la conversación
     * Esto garantiza que ambos dispositivos generen la misma clave
     * @param {number} userId1 - ID del primer usuario
     * @param {number} userId2 - ID del segundo usuario
     */
    async generateConversationKey(userId1, userId2) {
        try {
            // Ordenar los IDs para que siempre generen la misma clave sin importar quién envía
            const sortedIds = [userId1, userId2].sort((a, b) => a - b);
            const seed = `chat_seguro_${sortedIds[0]}_${sortedIds[1]}_v1`;
            
            DEBUG.crypto('Generando clave de conversación para usuarios: ' + sortedIds.join(' <-> '));
            DEBUG.crypto('Seed: ' + seed);
            
            const encoder = new TextEncoder();
            const seedData = encoder.encode(seed);
            
            let hashBuffer;
            if (this.isSecureContext) {
                hashBuffer = await crypto.subtle.digest('SHA-256', seedData);
            } else {
                hashBuffer = await this.sha256Fallback(seedData);
            }
            
            const key = this.arrayBufferToBase64(hashBuffer);
            DEBUG.crypto('Clave generada (primeros 20 chars): ' + key.substring(0, 20));
            return key;
        } catch (error) {
            DEBUG.error('Error generando clave de conversación: ' + error.message);
            throw error;
        }
    },

    /**
     * [DEPRECATED] Genera una clave AES basada en el token JWT
     * NOTA: No usar - cada dispositivo tiene token diferente
     */
    async generateSessionKey() {
        try {
            const token = localStorage.getItem(CONFIG.STORAGE_KEYS.ACCESS_TOKEN);
            if (!token) {
                throw new Error('No hay token de sesión');
            }
            
            DEBUG.crypto('Contexto seguro (HTTPS): ' + this.isSecureContext);
            
            // Derivar clave de 256 bits del token
            const encoder = new TextEncoder();
            const tokenData = encoder.encode(token);
            
            let hashBuffer;
            if (this.isSecureContext) {
                // Usar Web Crypto API (HTTPS/localhost)
                hashBuffer = await crypto.subtle.digest('SHA-256', tokenData);
            } else {
                // Fallback para HTTP (solo desarrollo)
                DEBUG.warn('Usando fallback SHA-256 (HTTP no seguro)');
                hashBuffer = await this.sha256Fallback(tokenData);
            }
            
            return this.arrayBufferToBase64(hashBuffer);
        } catch (error) {
            DEBUG.error('Error generando clave de sesión: ' + error.message);
            throw error;
        }
    },

    /**
     * Genera un IV (Vector de Inicialización) aleatorio
     */
    generateIV() {
        // Generar 16 bytes aleatorios (128 bits)
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return this.arrayBufferToBase64(array);
    },

    /**
     * Cifra un mensaje con AES-256-CBC
     * Con fallback XOR para HTTP (solo desarrollo)
     * NOTA: Si forceXorForCompatibility=true, SIEMPRE usa XOR
     */
    async encryptAES(message, key, iv) {
        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(message);
            
            // Determinar si usar AES o XOR
            const useAes = this.isSecureContext && !this.forceXorForCompatibility;
            
            if (useAes) {
                // Usar Web Crypto API (HTTPS/localhost)
                DEBUG.crypto('Usando cifrado AES-256-CBC');
                const keyData = this.base64ToArrayBuffer(key);
                const cryptoKey = await crypto.subtle.importKey(
                    'raw',
                    keyData,
                    { name: 'AES-CBC', length: 256 },
                    false,
                    ['encrypt']
                );
                
                const ivData = this.base64ToArrayBuffer(iv);
                const encrypted = await crypto.subtle.encrypt(
                    { name: 'AES-CBC', iv: ivData },
                    cryptoKey,
                    data
                );
                
                return this.arrayBufferToBase64(encrypted);
            } else {
                // Fallback: XOR simple para desarrollo HTTP o compatibilidad
                DEBUG.warn('Usando cifrado XOR (fallback/compatibilidad)');
                const keyData = this.base64ToArrayBuffer(key);
                const keyArray = new Uint8Array(keyData);
                const encrypted = new Uint8Array(data.length);
                
                for (let i = 0; i < data.length; i++) {
                    encrypted[i] = data[i] ^ keyArray[i % keyArray.length];
                }
                
                return this.arrayBufferToBase64(encrypted.buffer);
            }
        } catch (error) {
            DEBUG.error('Error cifrando con AES: ' + error.message);
            throw error;
        }
    },

    /**
     * Descifra un mensaje con AES-256-CBC
     * Con fallback XOR para HTTP (solo desarrollo)
     */
    async decryptAES(encryptedData, key, iv) {
        try {
            if (this.isSecureContext) {
                // Usar Web Crypto API (HTTPS/localhost)
                const keyData = this.base64ToArrayBuffer(key);
                const cryptoKey = await crypto.subtle.importKey(
                    'raw',
                    keyData,
                    { name: 'AES-CBC', length: 256 },
                    false,
                    ['decrypt']
                );
                
                const ivData = this.base64ToArrayBuffer(iv);
                const encryptedBuffer = this.base64ToArrayBuffer(encryptedData);
                const decrypted = await crypto.subtle.decrypt(
                    { name: 'AES-CBC', iv: ivData },
                    cryptoKey,
                    encryptedBuffer
                );
                
                const decoder = new TextDecoder();
                return decoder.decode(decrypted);
            } else {
                // Fallback: XOR simple para desarrollo HTTP
                DEBUG.warn('Usando descifrado XOR fallback (HTTP)');
                const keyData = this.base64ToArrayBuffer(key);
                const keyArray = new Uint8Array(keyData);
                const encryptedBuffer = this.base64ToArrayBuffer(encryptedData);
                const encryptedArray = new Uint8Array(encryptedBuffer);
                const decrypted = new Uint8Array(encryptedArray.length);
                
                for (let i = 0; i < encryptedArray.length; i++) {
                    decrypted[i] = encryptedArray[i] ^ keyArray[i % keyArray.length];
                }
                
                const decoder = new TextDecoder();
                return decoder.decode(decrypted);
            }
        } catch (error) {
            DEBUG.error('Error descifrando con AES: ' + error.message);
            throw error;
        }
    },

    /**
     * Descifra un mensaje con XOR (función separada para uso directo)
     * @param {string} encryptedData - Datos cifrados en Base64
     * @param {string} key - Clave en Base64
     * @returns {string} - Texto descifrado
     */
    xorDecrypt(encryptedData, key) {
        try {
            DEBUG.crypto('XOR decrypt iniciado');
            const keyData = this.base64ToArrayBuffer(key);
            const keyArray = new Uint8Array(keyData);
            const encryptedBuffer = this.base64ToArrayBuffer(encryptedData);
            const encryptedArray = new Uint8Array(encryptedBuffer);
            const decrypted = new Uint8Array(encryptedArray.length);
            
            for (let i = 0; i < encryptedArray.length; i++) {
                decrypted[i] = encryptedArray[i] ^ keyArray[i % keyArray.length];
            }
            
            const decoder = new TextDecoder();
            const result = decoder.decode(decrypted);
            DEBUG.crypto('XOR decrypt resultado: ' + result);
            return result;
        } catch (error) {
            DEBUG.error('Error en xorDecrypt: ' + error.message);
            throw error;
        }
    },

    /**
     * Simula el cifrado RSA
     * NOTA: En producción real, se debe usar forge.js o similar
     */
    async encryptRSA(data, publicKeyPEM) {
        // En la implementación completa, usar forge.js o Web Crypto API
        // Por ahora, retornamos un placeholder
        console.log('Cifrando con RSA (clave pública)...');
        return btoa(data); // Base64 simple como placeholder
    },

    /**
     * Simula el descifrado RSA
     */
    async decryptRSA(encryptedData, privateKeyPEM) {
        // En la implementación completa, usar forge.js o Web Crypto API
        console.log('Descifrando con RSA (clave privada)...');
        return atob(encryptedData); // Decodificar Base64 simple
    },

    /**
     * Crea un sobre de mensaje cifrado (híbrido RSA + AES)
     * @param {string} message - Mensaje a cifrar
     * @param {string} recipientPublicKey - Clave pública del destinatario (no usada en versión simplificada)
     * @param {number} senderId - ID del usuario que envía
     * @param {number} recipientId - ID del usuario que recibe
     */
    async createSecureEnvelope(message, recipientPublicKey, senderId, recipientId) {
        try {
            DEBUG.crypto('Creando sobre para: ' + message.substring(0, 30) + '...');
            DEBUG.crypto('Sender ID: ' + senderId + ', Recipient ID: ' + recipientId);
            DEBUG.crypto('Contexto seguro: ' + this.isSecureContext);
            DEBUG.crypto('Forzar XOR para compatibilidad: ' + this.forceXorForCompatibility);
            
            // Generar clave basada en los IDs de usuario (misma para ambos)
            DEBUG.crypto('Generando clave de conversación...');
            const aesKey = await this.generateConversationKey(senderId, recipientId);
            const iv = this.generateIV();
            
            // Determinar método de cifrado:
            // - Si forceXorForCompatibility = true, SIEMPRE usar XOR
            // - Si no, usar AES solo si hay contexto seguro
            const useAes = this.isSecureContext && !this.forceXorForCompatibility;
            const cryptoMethod = useAes ? 'aes' : 'xor';
            DEBUG.crypto('Método de cifrado: ' + cryptoMethod);
            
            const encryptedMessage = await this.encryptAES(message, aesKey, iv);
            DEBUG.crypto('Mensaje cifrado: ' + encryptedMessage.substring(0, 30) + '...');
            
            // Firma simplificada (solo hash SHA-256)
            const signature = await this.sign(message);
            DEBUG.crypto('Firma SHA-256 creada');
            
            // Crear sobre completo con indicador del método usado
            const envelope = {
                encrypted_message: encryptedMessage,
                iv: iv,
                signature: signature,
                timestamp: new Date().toISOString(),
                crypto_method: cryptoMethod,  // Indicar qué método se usó
                sender_id: senderId,          // Incluir IDs para descifrado
                recipient_id: recipientId
            };
            
            DEBUG.success('Sobre cifrado creado correctamente (método: ' + cryptoMethod + ')');
            return envelope;
        } catch (error) {
            DEBUG.error('Error creando sobre: ' + error.message);
            throw error;
        }
    },

    /**
     * Abre un sobre de mensaje cifrado
     * @param {object} envelope - Sobre cifrado con encrypted_message, iv, sender_id, recipient_id
     * @param {string} privateKey - Clave privada (no usada en versión simplificada)
     * @param {string} senderPublicKey - Clave pública del emisor (no usada)
     * @param {number} myUserId - ID del usuario actual (receptor)
     */
    async openSecureEnvelope(envelope, privateKey, senderPublicKey, myUserId) {
        try {
            DEBUG.crypto('Abriendo sobre cifrado...');
            DEBUG.crypto('Sobre recibido', envelope);
            
            // Detectar qué método se usó para cifrar
            const cryptoMethod = envelope.crypto_method || 'aes';
            DEBUG.crypto('Método de cifrado detectado: ' + cryptoMethod);
            
            // Obtener IDs de usuario del sobre o usar los parámetros
            const senderId = envelope.sender_id;
            const recipientId = envelope.recipient_id || myUserId;
            
            DEBUG.crypto('Sender ID: ' + senderId + ', Recipient ID: ' + recipientId);
            
            // Generar la misma clave de conversación
            DEBUG.crypto('Generando clave de conversación para descifrar...');
            const aesKey = await this.generateConversationKey(senderId, recipientId);
            
            // Validar que tenemos todos los datos necesarios
            if (!envelope.encrypted_message || !envelope.iv) {
                DEBUG.error('Sobre incompleto - faltan campos');
                throw new Error('Sobre incompleto: faltan datos de cifrado');
            }
            
            DEBUG.crypto('Descifrando mensaje...');
            DEBUG.crypto('encrypted_message: ' + envelope.encrypted_message);
            DEBUG.crypto('iv: ' + envelope.iv);
            
            let message;
            
            // Usar el método correcto para descifrar
            if (cryptoMethod === 'xor') {
                // Mensaje cifrado con XOR - usar XOR para descifrar
                DEBUG.crypto('Usando descifrado XOR (fallback)');
                message = this.xorDecrypt(envelope.encrypted_message, aesKey);
            } else {
                // Mensaje cifrado con AES - intentar AES primero
                if (this.isSecureContext && window.crypto && window.crypto.subtle) {
                    DEBUG.crypto('Usando descifrado AES-256-CBC');
                    message = await this.decryptAES(
                        envelope.encrypted_message,
                        aesKey,
                        envelope.iv
                    );
                } else {
                    // No tenemos Web Crypto pero el mensaje fue cifrado con AES
                    DEBUG.warn('ADVERTENCIA: Mensaje cifrado con AES pero no hay Web Crypto disponible');
                    try {
                        message = atob(envelope.encrypted_message);
                        message = '[AES-No disponible] ' + message.substring(0, 50) + '...';
                    } catch (e) {
                        message = '[No se puede descifrar: AES no disponible en HTTP]';
                    }
                }
            }
            
            DEBUG.success('Mensaje descifrado: ' + message);
            
            // Verificar firma (simplificado)
            let signatureValid = true;
            if (envelope.signature) {
                const expectedSignature = await this.sign(message);
                signatureValid = (expectedSignature === envelope.signature);
                DEBUG.crypto('Firma verificada: ' + (signatureValid ? 'VÁLIDA' : 'INVÁLIDA'));
            }
            
            return {
                message: message,
                signatureValid: signatureValid
            };
        } catch (error) {
            DEBUG.error('Error abriendo sobre: ' + error.message);
            DEBUG.error('Datos del sobre: ' + JSON.stringify(envelope));
            throw error;
        }
    },

    /**
     * Crea una firma digital (simplificada)
     * Con fallback para HTTP
     */
    async sign(data) {
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);
        
        let hashBuffer;
        if (this.isSecureContext) {
            hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
        } else {
            hashBuffer = await this.sha256Fallback(dataBuffer);
        }
        
        return this.arrayBufferToBase64(hashBuffer);
    },

    /**
     * Verifica una firma digital (simplificada)
     */
    async verify(data, signature, publicKey) {
        // En producción, verificar con RSA-PSS
        const computedSignature = await this.sign(data);
        return computedSignature === signature;
    },

    /**
     * Genera un nonce único para prevenir replay attacks
     */
    generateNonce() {
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return this.arrayBufferToBase64(array);
    },

    /**
     * Utilidades de conversión
     */
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    },

    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    },

    /**
     * Genera un hash SHA-256 de un string
     */
    async sha256(message) {
        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    }
};

// Exportar para uso en otros módulos
window.CryptoModule = CryptoModule;
