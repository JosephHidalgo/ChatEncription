// Módulo de criptografía para el cliente
// Soporta tanto Web Crypto API (HTTPS) como fallback para HTTP

const CryptoModule = {
    // Detectar si Web Crypto API está disponible
    isSecureContext: !!(window.crypto && window.crypto.subtle),
    
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
     * Genera una clave AES determinista basada en el token JWT
     * Esto permite que ambos dispositivos usen la misma clave (TEMPORAL)
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
     */
    async encryptAES(message, key, iv) {
        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(message);
            
            if (this.isSecureContext) {
                // Usar Web Crypto API (HTTPS/localhost)
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
                // Fallback: XOR simple para desarrollo HTTP
                DEBUG.warn('Usando cifrado XOR fallback (HTTP)');
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
     * NOTA: Versión simplificada - usa clave de sesión compartida
     */
    async createSecureEnvelope(message, recipientPublicKey) {
        try {
            DEBUG.crypto('Creando sobre para: ' + message.substring(0, 30) + '...');
            
            // Usar clave de sesión compartida (derivada del token)
            DEBUG.crypto('Generando clave de sesión...');
            const aesKey = await this.generateSessionKey();
            const iv = this.generateIV();
            
            DEBUG.crypto('Clave de sesión generada (primeros 20 chars): ' + aesKey.substring(0, 20));
            
            // Cifrar el mensaje con AES
            DEBUG.crypto('Cifrando con AES-256-CBC...');
            const encryptedMessage = await this.encryptAES(message, aesKey, iv);
            DEBUG.crypto('Mensaje cifrado: ' + encryptedMessage.substring(0, 30) + '...');
            
            // Firma simplificada (solo hash SHA-256)
            const signature = await this.sign(message);
            DEBUG.crypto('Firma SHA-256 creada');
            
            // Crear sobre completo (NO enviamos la clave porque es derivada del token)
            const envelope = {
                encrypted_message: encryptedMessage,
                iv: iv,
                signature: signature,
                timestamp: new Date().toISOString()
            };
            
            DEBUG.success('Sobre cifrado creado correctamente');
            return envelope;
        } catch (error) {
            DEBUG.error('Error creando sobre: ' + error.message);
            throw error;
        }
    },

    /**
     * Abre un sobre de mensaje cifrado
     * NOTA: Versión simplificada - usa clave de sesión compartida
     */
    async openSecureEnvelope(envelope, privateKey, senderPublicKey) {
        try {
            DEBUG.crypto('Abriendo sobre cifrado...');
            DEBUG.crypto('Sobre recibido', envelope);
            
            // Usar la misma clave de sesión (derivada del token)
            DEBUG.crypto('Generando clave de sesión para descifrar...');
            const aesKey = await this.generateSessionKey();
            DEBUG.crypto('Clave de sesión (primeros 20 chars): ' + aesKey.substring(0, 20));
            
            // Validar que tenemos todos los datos necesarios
            if (!envelope.encrypted_message || !envelope.iv) {
                DEBUG.error('Sobre incompleto - faltan campos');
                throw new Error('Sobre incompleto: faltan datos de cifrado');
            }
            
            DEBUG.crypto('Descifrando con AES-256-CBC...');
            DEBUG.crypto('encrypted_message: ' + envelope.encrypted_message);
            DEBUG.crypto('iv: ' + envelope.iv);
            
            // Descifrar el mensaje con AES
            const message = await this.decryptAES(
                envelope.encrypted_message,
                aesKey,
                envelope.iv
            );
            
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
