/**
 * Módulo de Criptografía - Cifrado Híbrido RSA + AES
 * 
 * Implementa el estándar de cifrado híbrido:
 * - AES-256-CBC para cifrar mensajes (eficiente para datos grandes)
 * - RSA-OAEP para cifrar la clave AES (seguro para intercambio de claves)
 * 
 * Flujo:
 * 1. Emisor genera clave AES aleatoria (32 bytes)
 * 2. Emisor cifra mensaje con AES-256-CBC
 * 3. Emisor cifra clave AES con clave pública RSA del destinatario
 * 4. Se envía: {mensaje_cifrado, clave_AES_cifrada, IV, firma}
 * 5. Receptor descifra clave AES con su clave privada RSA
 * 6. Receptor descifra mensaje con la clave AES
 * 
 * @version 10.0 - Cifrado Híbrido Estándar
 */

const CryptoModule = {
    // Detectar si Web Crypto API está disponible (requiere HTTPS o localhost)
    isSecureContext: !!(window.crypto && window.crypto.subtle),

    // ==================== UTILIDADES DE CONVERSIÓN ====================

    /**
     * Convierte ArrayBuffer a string Base64
     */
    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    },

    /**
     * Convierte string Base64 a ArrayBuffer
     */
    base64ToArrayBuffer(base64) {
        const binary = atob(base64);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    },

    // ==================== GENERACIÓN DE CLAVES ====================

    /**
     * Genera una clave AES-256 aleatoria (32 bytes)
     * @returns {Uint8Array} Clave AES como array de bytes
     */
    generateRandomAESKey() {
        const key = new Uint8Array(32); // 256 bits
        crypto.getRandomValues(key);
        return key;
    },

    /**
     * Genera un IV (Vector de Inicialización) aleatorio (16 bytes)
     * @returns {string} IV en formato Base64
     */
    generateIV() {
        const iv = new Uint8Array(16); // 128 bits
        crypto.getRandomValues(iv);
        return this.arrayBufferToBase64(iv);
    },

    /**
     * Genera un nonce único para prevenir replay attacks
     * @returns {string} Nonce en formato Base64
     */
    generateNonce() {
        const nonce = new Uint8Array(32);
        crypto.getRandomValues(nonce);
        return this.arrayBufferToBase64(nonce);
    },

    // ==================== CIFRADO AES-256-CBC ====================

    /**
     * Cifra un mensaje con AES-256-CBC
     * @param {string} message - Mensaje en texto plano
     * @param {Uint8Array} keyBytes - Clave AES de 32 bytes
     * @param {string} ivBase64 - IV en formato Base64
     * @returns {string} Mensaje cifrado en Base64
     */
    async encryptAES(message, keyBytes, ivBase64) {
        if (!this.isSecureContext) {
            throw new Error('Cifrado AES requiere contexto seguro (HTTPS)');
        }

        try {
            const encoder = new TextEncoder();
            const data = encoder.encode(message);

            // Importar clave AES
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                keyBytes,
                { name: 'AES-CBC', length: 256 },
                false,
                ['encrypt']
            );

            // Cifrar
            const ivBytes = this.base64ToArrayBuffer(ivBase64);
            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-CBC', iv: ivBytes },
                cryptoKey,
                data
            );

            return this.arrayBufferToBase64(encrypted);
        } catch (error) {
            console.error('Error en cifrado AES:', error);
            throw error;
        }
    },

    /**
     * Descifra un mensaje con AES-256-CBC
     * @param {string} encryptedBase64 - Mensaje cifrado en Base64
     * @param {Uint8Array} keyBytes - Clave AES de 32 bytes
     * @param {string} ivBase64 - IV en formato Base64
     * @returns {string} Mensaje descifrado
     */
    async decryptAES(encryptedBase64, keyBytes, ivBase64) {
        if (!this.isSecureContext) {
            throw new Error('Descifrado AES requiere contexto seguro (HTTPS)');
        }

        try {
            // Importar clave AES
            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                keyBytes,
                { name: 'AES-CBC', length: 256 },
                false,
                ['decrypt']
            );

            // Descifrar
            const ivBytes = this.base64ToArrayBuffer(ivBase64);
            const encryptedBytes = this.base64ToArrayBuffer(encryptedBase64);
            
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-CBC', iv: ivBytes },
                cryptoKey,
                encryptedBytes
            );

            const decoder = new TextDecoder();
            return decoder.decode(decrypted);
        } catch (error) {
            console.error('Error en descifrado AES:', error);
            throw error;
        }
    },

    // ==================== CIFRADO RSA-OAEP ====================

    /**
     * Importa una clave pública RSA desde formato PEM
     * @param {string} pemKey - Clave pública en formato PEM
     * @returns {CryptoKey} Clave pública importada
     */
    async importPublicKey(pemKey) {
        try {
            // Eliminar header/footer del PEM y espacios
            const pemHeader = '-----BEGIN PUBLIC KEY-----';
            const pemFooter = '-----END PUBLIC KEY-----';
            const pemContents = pemKey
                .replace(pemHeader, '')
                .replace(pemFooter, '')
                .replace(/\s/g, '');

            // Decodificar Base64 a bytes
            const binaryString = atob(pemContents);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }

            // Importar como clave RSA-OAEP
            return await crypto.subtle.importKey(
                'spki',
                bytes.buffer,
                {
                    name: 'RSA-OAEP',
                    hash: 'SHA-256'
                },
                true,
                ['encrypt']
            );
        } catch (error) {
            console.error('Error importando clave pública:', error);
            throw new Error('No se pudo importar la clave pública RSA');
        }
    },

    /**
     * Importa una clave privada RSA desde formato PEM
     * @param {string} pemKey - Clave privada en formato PEM
     * @returns {CryptoKey} Clave privada importada
     */
    async importPrivateKey(pemKey) {
        try {
            // Eliminar header/footer del PEM y espacios
            const pemHeader = '-----BEGIN PRIVATE KEY-----';
            const pemFooter = '-----END PRIVATE KEY-----';
            const pemContents = pemKey
                .replace(pemHeader, '')
                .replace(pemFooter, '')
                .replace(/\s/g, '');

            // Decodificar Base64 a bytes
            const binaryString = atob(pemContents);
            const bytes = new Uint8Array(binaryString.length);
            for (let i = 0; i < binaryString.length; i++) {
                bytes[i] = binaryString.charCodeAt(i);
            }

            // Importar como clave RSA-OAEP
            return await crypto.subtle.importKey(
                'pkcs8',
                bytes.buffer,
                {
                    name: 'RSA-OAEP',
                    hash: 'SHA-256'
                },
                true,
                ['decrypt']
            );
        } catch (error) {
            console.error('Error importando clave privada:', error);
            throw new Error('No se pudo importar la clave privada RSA');
        }
    },

    /**
     * Cifra datos con RSA-OAEP usando clave pública
     * @param {Uint8Array} data - Datos a cifrar (máximo ~190 bytes para RSA-2048)
     * @param {string} publicKeyPEM - Clave pública en formato PEM
     * @returns {string} Datos cifrados en Base64
     */
    async encryptRSA(data, publicKeyPEM) {
        if (!this.isSecureContext) {
            throw new Error('Cifrado RSA requiere contexto seguro (HTTPS)');
        }

        try {
            DEBUG.crypto('Cifrando con RSA-OAEP...');
            
            // Importar clave pública
            const publicKey = await this.importPublicKey(publicKeyPEM);

            // Cifrar con RSA-OAEP
            const encrypted = await crypto.subtle.encrypt(
                { name: 'RSA-OAEP' },
                publicKey,
                data
            );

            DEBUG.crypto('Clave AES cifrada con RSA exitosamente');
            return this.arrayBufferToBase64(encrypted);
        } catch (error) {
            console.error('Error en cifrado RSA:', error);
            throw error;
        }
    },

    /**
     * Descifra datos con RSA-OAEP usando clave privada
     * @param {string} encryptedBase64 - Datos cifrados en Base64
     * @param {string} privateKeyPEM - Clave privada en formato PEM
     * @returns {Uint8Array} Datos descifrados como array de bytes
     */
    async decryptRSA(encryptedBase64, privateKeyPEM) {
        if (!this.isSecureContext) {
            throw new Error('Descifrado RSA requiere contexto seguro (HTTPS)');
        }

        try {
            DEBUG.crypto('Descifrando con RSA-OAEP...');
            
            // Importar clave privada
            const privateKey = await this.importPrivateKey(privateKeyPEM);

            // Descifrar con RSA-OAEP
            const encryptedBytes = this.base64ToArrayBuffer(encryptedBase64);
            const decrypted = await crypto.subtle.decrypt(
                { name: 'RSA-OAEP' },
                privateKey,
                encryptedBytes
            );

            DEBUG.crypto('Clave AES descifrada con RSA exitosamente');
            return new Uint8Array(decrypted);
        } catch (error) {
            console.error('Error en descifrado RSA:', error);
            throw error;
        }
    },

    // ==================== FIRMA DIGITAL ====================

    /**
     * Crea una firma digital (hash SHA-256 del mensaje)
     * @param {string} message - Mensaje a firmar
     * @returns {string} Firma en Base64
     */
    async sign(message) {
        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        
        if (this.isSecureContext) {
            const hashBuffer = await crypto.subtle.digest('SHA-256', data);
            return this.arrayBufferToBase64(hashBuffer);
        } else {
            // Fallback simple para desarrollo
            let hash = 0;
            for (let i = 0; i < message.length; i++) {
                const char = message.charCodeAt(i);
                hash = ((hash << 5) - hash) + char;
                hash = hash & hash;
            }
            return btoa(hash.toString());
        }
    },

    /**
     * Verifica una firma digital
     * @param {string} message - Mensaje original
     * @param {string} signature - Firma a verificar
     * @returns {boolean} true si la firma es válida
     */
    async verify(message, signature) {
        const computedSignature = await this.sign(message);
        return computedSignature === signature;
    },

    // ==================== CIFRADO HÍBRIDO (RSA + AES) ====================

    /**
     * Crea un sobre cifrado usando cifrado híbrido RSA + AES
     * 
     * FLUJO:
     * 1. Generar clave AES aleatoria (32 bytes)
     * 2. Generar IV aleatorio (16 bytes)
     * 3. Cifrar mensaje con AES-256-CBC
     * 4. Cifrar clave AES con RSA para AMBOS: destinatario Y emisor
     * 5. Crear firma del mensaje original
     * 
     * NOTA: La clave AES se cifra dos veces para que tanto el emisor
     * como el destinatario puedan descifrar el mensaje posteriormente.
     * 
     * @param {string} message - Mensaje a cifrar
     * @param {string} recipientPublicKey - Clave pública RSA del destinatario (PEM)
     * @param {number} senderId - ID del usuario emisor
     * @param {number} recipientId - ID del usuario destinatario
     * @param {string} senderPublicKey - Clave pública RSA del emisor (PEM) - OPCIONAL
     * @returns {object} Sobre cifrado
     */
    async createSecureEnvelope(message, recipientPublicKey, senderId, recipientId, senderPublicKey = null) {
        try {
            DEBUG.crypto('══════════════════════════════════════════');
            DEBUG.crypto('   CREANDO SOBRE CIFRADO (RSA + AES)');
            DEBUG.crypto('══════════════════════════════════════════');
            DEBUG.crypto('Mensaje: "' + message.substring(0, 50) + (message.length > 50 ? '..."' : '"'));
            DEBUG.crypto('Emisor ID: ' + senderId);
            DEBUG.crypto('Destinatario ID: ' + recipientId);

            if (!this.isSecureContext) {
                throw new Error('El cifrado híbrido requiere HTTPS. Por favor usa una conexión segura.');
            }

            if (!recipientPublicKey) {
                throw new Error('Se requiere la clave pública del destinatario');
            }

            // PASO 1: Generar clave AES aleatoria (única para este mensaje)
            DEBUG.crypto('');
            DEBUG.crypto('PASO 1: Generando clave AES-256 aleatoria...');
            const aesKey = this.generateRandomAESKey();
            DEBUG.crypto('  ✓ Clave AES generada (32 bytes aleatorios)');

            // PASO 2: Generar IV aleatorio
            DEBUG.crypto('');
            DEBUG.crypto('PASO 2: Generando IV aleatorio...');
            const iv = this.generateIV();
            DEBUG.crypto('  ✓ IV generado (16 bytes aleatorios)');

            // PASO 3: Cifrar mensaje con AES-256-CBC
            DEBUG.crypto('');
            DEBUG.crypto('PASO 3: Cifrando mensaje con AES-256-CBC...');
            const encryptedMessage = await this.encryptAES(message, aesKey, iv);
            DEBUG.crypto('  ✓ Mensaje cifrado: ' + encryptedMessage.substring(0, 30) + '...');

            // PASO 4: Cifrar clave AES con RSA para el DESTINATARIO
            DEBUG.crypto('');
            DEBUG.crypto('PASO 4: Cifrando clave AES con RSA-OAEP...');
            DEBUG.crypto('  4a. Usando clave pública del DESTINATARIO');
            const encryptedAesKeyForRecipient = await this.encryptRSA(aesKey, recipientPublicKey);
            DEBUG.crypto('  ✓ Clave AES cifrada para destinatario');

            // PASO 4b: Cifrar clave AES con RSA para el EMISOR (yo mismo)
            let encryptedAesKeyForSender = null;
            if (senderPublicKey) {
                DEBUG.crypto('  4b. Usando clave pública del EMISOR (para mi historial)');
                encryptedAesKeyForSender = await this.encryptRSA(aesKey, senderPublicKey);
                DEBUG.crypto('  ✓ Clave AES cifrada para emisor');
            } else {
                DEBUG.warn('  ⚠ No se proporcionó clave pública del emisor');
            }

            // PASO 5: Crear firma del mensaje original
            DEBUG.crypto('');
            DEBUG.crypto('PASO 5: Creando firma digital (SHA-256)...');
            const signature = await this.sign(message);
            DEBUG.crypto('  ✓ Firma creada');

            // Crear sobre completo
            const envelope = {
                // Datos cifrados
                encrypted_message: encryptedMessage,              // Mensaje cifrado con AES
                encrypted_key: encryptedAesKeyForRecipient,       // Clave AES cifrada para DESTINATARIO
                encrypted_key_sender: encryptedAesKeyForSender,   // Clave AES cifrada para EMISOR
                iv: iv,                                           // Vector de inicialización
                
                // Metadatos de seguridad
                signature: signature,                    // Firma digital
                nonce: this.generateNonce(),            // Anti-replay
                timestamp: new Date().toISOString(),    // Timestamp
                
                // Identificadores
                sender_id: senderId,
                recipient_id: recipientId,
                
                // Versión del protocolo
                crypto_version: '2.0',
                crypto_method: 'RSA_AES_HYBRID'
            };

            DEBUG.crypto('');
            DEBUG.crypto('══════════════════════════════════════════');
            DEBUG.success('✓ SOBRE CIFRADO CREADO EXITOSAMENTE');
            DEBUG.crypto('  Método: RSA-OAEP + AES-256-CBC');
            DEBUG.crypto('══════════════════════════════════════════');

            return envelope;
        } catch (error) {
            DEBUG.error('Error creando sobre cifrado: ' + error.message);
            throw error;
        }
    },

    /**
     * Abre un sobre cifrado usando cifrado híbrido RSA + AES
     * 
     * FLUJO:
     * 1. Descifrar clave AES con RSA (mi clave privada)
     * 2. Descifrar mensaje con AES-256-CBC
     * 3. Verificar firma digital
     * 
     * @param {object} envelope - Sobre cifrado
     * @param {string} myPrivateKey - MI clave privada RSA (PEM)
     * @param {string} senderPublicKey - Clave pública del emisor (para verificación futura)
     * @param {number} myUserId - Mi ID de usuario
     * @returns {object} {message: string, signatureValid: boolean}
     */
    async openSecureEnvelope(envelope, myPrivateKey, senderPublicKey, myUserId) {
        try {
            DEBUG.crypto('══════════════════════════════════════════');
            DEBUG.crypto('   ABRIENDO SOBRE CIFRADO (RSA + AES)');
            DEBUG.crypto('══════════════════════════════════════════');
            DEBUG.crypto('Método detectado: ' + (envelope.crypto_method || 'legacy'));
            DEBUG.crypto('Versión: ' + (envelope.crypto_version || '1.0'));

            // Verificar que es un sobre con cifrado híbrido
            if (envelope.crypto_method === 'RSA_AES_HYBRID' || envelope.encrypted_key) {
                // CIFRADO HÍBRIDO RSA + AES
                
                if (!myPrivateKey) {
                    throw new Error('Se requiere clave privada para descifrar. Inicia sesión nuevamente.');
                }

                if (!envelope.encrypted_key) {
                    throw new Error('El sobre no contiene la clave AES cifrada');
                }

                if (!envelope.encrypted_message || !envelope.iv) {
                    throw new Error('Sobre incompleto: faltan datos de cifrado');
                }

                // PASO 1: Descifrar clave AES con RSA (mi clave privada)
                // Determinar si soy el emisor o el destinatario para usar la clave correcta
                DEBUG.crypto('');
                DEBUG.crypto('PASO 1: Descifrando clave AES con RSA-OAEP...');
                DEBUG.crypto('  Mi user ID: ' + myUserId);
                DEBUG.crypto('  Sender ID del sobre: ' + envelope.sender_id);
                DEBUG.crypto('  Recipient ID del sobre: ' + envelope.recipient_id);
                
                const amISender = (envelope.sender_id === myUserId);
                DEBUG.crypto('  ¿Soy el emisor? ' + (amISender ? 'SÍ' : 'NO'));
                
                let encryptedKeyToUse;
                if (amISender && envelope.encrypted_key_sender) {
                    // Soy el emisor - usar la clave cifrada para mí
                    DEBUG.crypto('  → Usando encrypted_key_sender (clave para EMISOR)');
                    encryptedKeyToUse = envelope.encrypted_key_sender;
                } else {
                    // Soy el destinatario - usar la clave cifrada para el destinatario
                    DEBUG.crypto('  → Usando encrypted_key (clave para DESTINATARIO)');
                    encryptedKeyToUse = envelope.encrypted_key;
                }
                
                DEBUG.crypto('  Usando MI clave privada para descifrar...');
                const aesKey = await this.decryptRSA(encryptedKeyToUse, myPrivateKey);
                DEBUG.crypto('  ✓ Clave AES recuperada (32 bytes)');

                // PASO 2: Descifrar mensaje con AES-256-CBC
                DEBUG.crypto('');
                DEBUG.crypto('PASO 2: Descifrando mensaje con AES-256-CBC...');
                const message = await this.decryptAES(envelope.encrypted_message, aesKey, envelope.iv);
                DEBUG.crypto('  ✓ Mensaje descifrado: "' + message.substring(0, 30) + (message.length > 30 ? '..."' : '"'));

                // PASO 3: Verificar firma
                DEBUG.crypto('');
                DEBUG.crypto('PASO 3: Verificando firma digital...');
                let signatureValid = true;
                if (envelope.signature) {
                    signatureValid = await this.verify(message, envelope.signature);
                    DEBUG.crypto('  ' + (signatureValid ? '✓ Firma VÁLIDA' : '✗ Firma INVÁLIDA'));
                } else {
                    DEBUG.warn('  ⚠ Sin firma digital');
                }

                DEBUG.crypto('');
                DEBUG.crypto('══════════════════════════════════════════');
                DEBUG.success('✓ MENSAJE DESCIFRADO EXITOSAMENTE');
                DEBUG.crypto('══════════════════════════════════════════');

                return {
                    message: message,
                    signatureValid: signatureValid
                };
            } else {
                // FALLBACK: Método antiguo (derivación de claves desde IDs)
                // Esto es para compatibilidad con mensajes antiguos
                DEBUG.warn('⚠ Usando método de descifrado antiguo (compatibilidad)');
                return await this.openLegacyEnvelope(envelope, myUserId);
            }
        } catch (error) {
            DEBUG.error('Error abriendo sobre: ' + error.message);
            throw error;
        }
    },

    /**
     * [LEGACY] Abre sobres con el método antiguo (derivación de claves desde IDs)
     * Solo para compatibilidad con mensajes existentes
     */
    async openLegacyEnvelope(envelope, myUserId) {
        DEBUG.warn('Usando método LEGACY - Solo para mensajes antiguos');
        
        const senderId = envelope.sender_id;
        const recipientId = envelope.recipient_id || myUserId;

        // Generar clave desde IDs (método antiguo)
        const sortedIds = [senderId, recipientId].sort((a, b) => a - b);
        const seed = `chat_seguro_${sortedIds[0]}_${sortedIds[1]}_v1`;
        
        const encoder = new TextEncoder();
        const seedData = encoder.encode(seed);
        const hashBuffer = await crypto.subtle.digest('SHA-256', seedData);
        const aesKey = new Uint8Array(hashBuffer);

        // Descifrar
        const message = await this.decryptAES(envelope.encrypted_message, aesKey, envelope.iv);
        
        // Verificar firma
        let signatureValid = true;
        if (envelope.signature) {
            signatureValid = await this.verify(message, envelope.signature);
        }

        return {
            message: message,
            signatureValid: signatureValid
        };
    }
};

// Exportar para uso global
window.CryptoModule = CryptoModule;
