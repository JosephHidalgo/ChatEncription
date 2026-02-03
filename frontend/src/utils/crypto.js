const CryptoModule = {
    isSecureContext: !!(window.crypto && window.crypto.subtle),
    debugMode: true, // Activar logs de debug

    log(operation, data) {
        if (!this.debugMode) return;
        // console.group(`🔐 [CRYPTO] ${operation}`);
        // console.log(data);
        // console.groupEnd();
    },

    // ==================== UTILIDADES DE CONVERSIÓN ====================

    arrayBufferToBase64(buffer) {
        const bytes = new Uint8Array(buffer);

        const CHUNK_SIZE = 0x4000;
        const chunks = [];

        for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
            const chunk = bytes.subarray(i, Math.min(i + CHUNK_SIZE, bytes.length));
            const chunkArray = Array.from(chunk);
            chunks.push(String.fromCharCode(...chunkArray));
        }

        const binary = chunks.join('');
        return btoa(binary);
    },

    base64ToArrayBuffer(base64) {
        try {
            const binary = atob(base64);
            const bytes = new Uint8Array(binary.length);

            // Usar un loop simple sin operaciones complejas
            for (let i = 0; i < binary.length; i++) {
                bytes[i] = binary.charCodeAt(i) & 0xFF; // Asegurar que sea un byte válido
            }

            return bytes.buffer;
        } catch (error) {
            // console.error('Error en base64ToArrayBuffer:', error);
            throw new Error('Error decodificando base64: ' + error.message);
        }
    },

    /**
     * Extrae el contenido base64 de una clave PEM
     * Elimina headers, footers y saltos de línea
     */
    pemToBase64(pem) {
        if (!pem) return pem;

        this.log('pemToBase64 - Input', {
            pemLength: pem.length,
            pemStart: pem.substring(0, 50) + '...',
            hasPemHeaders: pem.includes('-----BEGIN')
        });

        const cleaned = pem
            .replace(/-----BEGIN [A-Z ]+-----/g, '')
            .replace(/-----END [A-Z ]+-----/g, '')
            .replace(/\s/g, '');

        this.log('pemToBase64 - Output', {
            cleanedLength: cleaned.length,
            cleanedStart: cleaned.substring(0, 50) + '...'
        });

        return cleaned;
    },

    // ==================== GENERACIÓN DE CLAVES ====================

    generateRandomAESKey() {
        const key = new Uint8Array(32); // 256 bits
        crypto.getRandomValues(key);
        return key;
    },

    generateIV() {
        const iv = new Uint8Array(16); // 128 bits
        crypto.getRandomValues(iv);
        return this.arrayBufferToBase64(iv);
    },

    generateNonce() {
        const nonce = new Uint8Array(32);
        crypto.getRandomValues(nonce);
        return this.arrayBufferToBase64(nonce);
    },

    // ==================== CIFRADO AES-256-CBC ====================

    async encryptAES(message, keyBytes, ivBase64) {
        if (!this.isSecureContext) {
            throw new Error('Cifrado AES requiere contexto seguro (HTTPS)');
        }

        try {
            // Validar inputs
            if (!message || typeof message !== 'string') {
                throw new Error('Mensaje inválido para cifrado');
            }

            if (!keyBytes || keyBytes.length !== 32) {
                throw new Error('Clave AES debe ser de 32 bytes (256 bits)');
            }

            if (!ivBase64) {
                throw new Error('IV es requerido');
            }

            const encoder = new TextEncoder();
            const data = encoder.encode(message);

            // Asegurar que keyBytes es un Uint8Array válido
            const keyArray = keyBytes instanceof Uint8Array ? keyBytes : new Uint8Array(keyBytes);

            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                keyArray,
                { name: 'AES-CBC', length: 256 },
                false,
                ['encrypt']
            );

            const iv = this.base64ToArrayBuffer(ivBase64);

            // Validar IV
            if (iv.byteLength !== 16) {
                throw new Error('IV debe ser de 16 bytes (128 bits)');
            }

            const encrypted = await crypto.subtle.encrypt(
                { name: 'AES-CBC', iv: iv },
                cryptoKey,
                data
            );

            return this.arrayBufferToBase64(encrypted);
        } catch (error) {
            // console.error('Error cifrando con AES:', error);
            throw error;
        }
    },

    async decryptAES(encryptedBase64, keyBytes, ivBase64) {
        if (!this.isSecureContext) {
            throw new Error('Descifrado AES requiere contexto seguro (HTTPS)');
        }

        try {
            // Validar inputs
            if (!encryptedBase64 || typeof encryptedBase64 !== 'string') {
                throw new Error('Datos cifrados inválidos');
            }

            if (!keyBytes || keyBytes.length !== 32) {
                throw new Error('Clave AES debe ser de 32 bytes (256 bits)');
            }

            if (!ivBase64) {
                throw new Error('IV es requerido');
            }

            // Asegurar que keyBytes es un Uint8Array válido
            const keyArray = keyBytes instanceof Uint8Array ? keyBytes : new Uint8Array(keyBytes);

            const cryptoKey = await crypto.subtle.importKey(
                'raw',
                keyArray,
                { name: 'AES-CBC', length: 256 },
                false,
                ['decrypt']
            );

            const iv = this.base64ToArrayBuffer(ivBase64);

            // Validar IV
            if (iv.byteLength !== 16) {
                throw new Error('IV debe ser de 16 bytes (128 bits)');
            }

            const encrypted = this.base64ToArrayBuffer(encryptedBase64);

            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-CBC', iv: iv },
                cryptoKey,
                encrypted
            );

            const decoder = new TextDecoder();
            return decoder.decode(decrypted);
        } catch (error) {
            // console.error('❌ Error descifrando con AES:', error);
            // console.error('   Detalles:', {
            //     encryptedLength: encryptedBase64?.length,
            //     keyLength: keyBytes?.length,
            //     ivLength: ivBase64?.length,
            //     errorMessage: error.message
            // });
            throw error;
        }
    },

    // ==================== CIFRADO RSA ====================

    async generateRSAKeyPair() {
        if (!this.isSecureContext) {
            throw new Error('Generación de claves RSA requiere contexto seguro (HTTPS)');
        }

        try {
            const keyPair = await crypto.subtle.generateKey(
                {
                    name: 'RSA-OAEP',
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: 'SHA-256'
                },
                true,
                ['encrypt', 'decrypt']
            );

            const publicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey);
            const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

            return {
                publicKey: this.arrayBufferToBase64(publicKey),
                privateKey: this.arrayBufferToBase64(privateKey)
            };
        } catch (error) {
            // console.error('Error generando par de claves RSA:', error);
            throw error;
        }
    },

    async encryptRSA(data, publicKeyBase64) {
        if (!this.isSecureContext) {
            throw new Error('Cifrado RSA requiere contexto seguro (HTTPS)');
        }

        try {
            this.log('encryptRSA - Start', {
                dataType: typeof data,
                dataLength: typeof data === 'string' ? data.length : data.byteLength,
                publicKeyLength: publicKeyBase64?.length,
                publicKeyStart: publicKeyBase64?.substring(0, 50) + '...'
            });

            // Limpiar formato PEM si es necesario
            const cleanBase64 = this.pemToBase64(publicKeyBase64);
            const publicKeyBuffer = this.base64ToArrayBuffer(cleanBase64);
            const publicKey = await crypto.subtle.importKey(
                'spki',
                publicKeyBuffer,
                { name: 'RSA-OAEP', hash: 'SHA-256' },
                false,
                ['encrypt']
            );

            this.log('encryptRSA - Key Imported', { keyType: 'RSA-OAEP' });

            const dataBuffer = typeof data === 'string'
                ? new TextEncoder().encode(data)
                : data;

            const encrypted = await crypto.subtle.encrypt(
                { name: 'RSA-OAEP' },
                publicKey,
                dataBuffer
            );

            const result = this.arrayBufferToBase64(encrypted);

            this.log('encryptRSA - Success', {
                encryptedLength: result.length,
                encryptedStart: result.substring(0, 50) + '...'
            });

            return result;
        } catch (error) {
            // console.error('Error cifrando con RSA:', error);
            throw error;
        }
    },

    async decryptRSA(encryptedBase64, privateKeyBase64) {
        if (!this.isSecureContext) {
            throw new Error('Descifrado RSA requiere contexto seguro (HTTPS)');
        }

        try {
            // Limpiar formato PEM si es necesario
            const cleanBase64 = this.pemToBase64(privateKeyBase64);
            const privateKeyBuffer = this.base64ToArrayBuffer(cleanBase64);
            const privateKey = await crypto.subtle.importKey(
                'pkcs8',
                privateKeyBuffer,
                { name: 'RSA-OAEP', hash: 'SHA-256' },
                false,
                ['decrypt']
            );

            const encrypted = this.base64ToArrayBuffer(encryptedBase64);
            const decrypted = await crypto.subtle.decrypt(
                { name: 'RSA-OAEP' },
                privateKey,
                encrypted
            );

            return decrypted;
        } catch (error) {
            // console.error('Error descifrando con RSA:', error);
            throw error;
        }
    },

    // ==================== CIFRADO HÍBRIDO ====================

    async encryptMessage(message, recipientPublicKey) {
        try {
            this.log('encryptMessage - Start', {
                messageLength: message?.length,
                hasRecipientKey: !!recipientPublicKey
            });

            const aesKey = this.generateRandomAESKey();
            const iv = this.generateIV();
            const nonce = this.generateNonce();

            this.log('encryptMessage - Keys Generated', {
                aesKeyLength: aesKey.length,
                ivLength: iv.length,
                nonceLength: nonce.length
            });

            const encryptedMessage = await this.encryptAES(message, aesKey, iv);
            const encryptedAESKey = await this.encryptRSA(aesKey, recipientPublicKey);

            const result = {
                encrypted_message: encryptedMessage,
                encrypted_key: encryptedAESKey,
                iv: iv,
                nonce: nonce
            };

            this.log('encryptMessage - Success', {
                encrypted_message_length: encryptedMessage.length,
                encrypted_key_length: encryptedAESKey.length
            });

            return result;
        } catch (error) {
            // console.error('Error en cifrado híbrido:', error);
            throw error;
        }
    },

    async decryptMessage(encryptedData, privateKey) {
        try {
            // console.group('🔓 Desencriptando mensaje...');
            // console.log('📦 Datos cifrados recibidos:');
            // console.log('  • Mensaje cifrado:', encryptedData?.encrypted_message?.substring(0, 50) + '...');
            // console.log('  • Clave AES cifrada:', encryptedData?.encrypted_key?.substring(0, 50) + '...');
            // console.log('  • IV:', encryptedData?.iv);

            // Validar que tenemos todos los datos necesarios
            if (!encryptedData) {
                throw new Error('No se recibieron datos cifrados');
            }

            const { encrypted_message, encrypted_key, iv } = encryptedData;

            if (!encrypted_message || !encrypted_key || !iv) {
                throw new Error('Datos cifrados incompletos: ' +
                    JSON.stringify({
                        hasMessage: !!encrypted_message,
                        hasKey: !!encrypted_key,
                        hasIV: !!iv
                    })
                );
            }

            if (!privateKey) {
                throw new Error('No se proporcionó clave privada');
            }

            // console.log('\n🔑 Paso 1: Descifrando clave AES con RSA-OAEP...');
            // console.log('  • Clave privada (longitud):', privateKey?.length, 'chars');

            let aesKeyBuffer;
            try {
                aesKeyBuffer = await this.decryptRSA(encrypted_key, privateKey);
            } catch (rsaError) {
                // console.error('  ❌ Error en descifrado RSA:', rsaError);
                throw new Error('Error descifrando clave AES con RSA: ' + rsaError.message);
            }

            const aesKey = new Uint8Array(aesKeyBuffer);
            // console.log('  ✓ Clave AES descifrada:', aesKey.length, 'bytes');

            if (aesKey.length !== 32) {
                throw new Error(`Clave AES tiene tamaño incorrecto: ${aesKey.length} bytes (esperado: 32)`);
            }

            // console.log('\n📝 Paso 2: Descifrando mensaje con AES-256-CBC...');
            // console.log('  • Algoritmo: AES-256-CBC');
            // console.log('  • Longitud clave:', aesKey.length * 8, 'bits');
            // console.log('  • IV length:', iv.length, 'chars');

            let message;
            try {
                message = await this.decryptAES(encrypted_message, aesKey, iv);
            } catch (aesError) {
                // console.error('  ❌ Error en descifrado AES:', aesError);
                throw new Error('Error descifrando mensaje con AES: ' + aesError.message);
            }

            // console.log('  ✓ Mensaje descifrado:', message.substring(0, 100));

            // console.log('\n✅ Desencriptación completada exitosamente');
            // console.groupEnd();

            return message;
        } catch (error) {
            // console.error('❌ Error en descifrado:', error);
            // console.error('   Stack:', error.stack);
            // console.groupEnd();
            throw error;
        }
    },

    // ==================== FIRMAS DIGITALES ====================

    async generateSigningKeyPair() {
        if (!this.isSecureContext) {
            throw new Error('Generación de claves de firma requiere contexto seguro (HTTPS)');
        }

        try {
            const keyPair = await crypto.subtle.generateKey(
                {
                    name: 'RSA-PSS',
                    modulusLength: 2048,
                    publicExponent: new Uint8Array([1, 0, 1]),
                    hash: 'SHA-256'
                },
                true,
                ['sign', 'verify']
            );

            const publicKey = await crypto.subtle.exportKey('spki', keyPair.publicKey);
            const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

            return {
                publicKey: this.arrayBufferToBase64(publicKey),
                privateKey: this.arrayBufferToBase64(privateKey)
            };
        } catch (error) {
            // console.error('Error generando claves de firma:', error);
            throw error;
        }
    },

    async signMessage(message, privateKeyBase64) {
        if (!this.isSecureContext) {
            throw new Error('Firma de mensajes requiere contexto seguro (HTTPS)');
        }

        try {
            // Limpiar formato PEM si es necesario
            const cleanBase64 = this.pemToBase64(privateKeyBase64);
            const privateKeyBuffer = this.base64ToArrayBuffer(cleanBase64);
            const privateKey = await crypto.subtle.importKey(
                'pkcs8',
                privateKeyBuffer,
                { name: 'RSA-PSS', hash: 'SHA-256' },
                false,
                ['sign']
            );

            const encoder = new TextEncoder();
            const data = encoder.encode(message);

            const signature = await crypto.subtle.sign(
                { name: 'RSA-PSS', saltLength: 32 },
                privateKey,
                data
            );

            return this.arrayBufferToBase64(signature);
        } catch (error) {
            // console.error('Error firmando mensaje:', error);
            throw error;
        }
    },

    async verifySignature(message, signatureBase64, publicKeyBase64) {
        if (!this.isSecureContext) {
            throw new Error('Verificación de firma requiere contexto seguro (HTTPS)');
        }

        try {
            // Limpiar formato PEM si es necesario
            const cleanBase64 = this.pemToBase64(publicKeyBase64);
            const publicKeyBuffer = this.base64ToArrayBuffer(cleanBase64);
            const publicKey = await crypto.subtle.importKey(
                'spki',
                publicKeyBuffer,
                { name: 'RSA-PSS', hash: 'SHA-256' },
                false,
                ['verify']
            );

            const encoder = new TextEncoder();
            const data = encoder.encode(message);
            const signature = this.base64ToArrayBuffer(signatureBase64);

            const isValid = await crypto.subtle.verify(
                { name: 'RSA-PSS', saltLength: 32 },
                publicKey,
                signature,
                data
            );

            return isValid;
        } catch (error) {
            // console.error('Error verificando firma:', error);
            return false;
        }
    },

    // ==================== CIFRADO DE CLAVE PRIVADA CON PASSWORD ====================

    /**
     * Deriva una clave AES-256 de una contraseña usando PBKDF2
     */
    async deriveKeyFromPassword(password, salt) {
        if (!this.isSecureContext) {
            throw new Error('Derivación de clave requiere contexto seguro (HTTPS)');
        }

        const encoder = new TextEncoder();
        const passwordBuffer = encoder.encode(password);

        // Importar la contraseña como clave
        const baseKey = await crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            'PBKDF2',
            false,
            ['deriveBits', 'deriveKey']
        );

        // Derivar clave AES usando PBKDF2
        const derivedKey = await crypto.subtle.deriveKey(
            {
                name: 'PBKDF2',
                salt: salt,
                iterations: 100000,
                hash: 'SHA-256'
            },
            baseKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );

        return derivedKey;
    },

    async encryptPrivateKeyWithPassword(privateKeyPEM, password) {
        if (!this.isSecureContext) {
            throw new Error('Cifrado requiere contexto seguro (HTTPS)');
        }

        try {
            // Generar salt e IV aleatorios
            const salt = new Uint8Array(16);
            crypto.getRandomValues(salt);

            const iv = new Uint8Array(12); // GCM recomienda 12 bytes
            crypto.getRandomValues(iv);

            // Derivar clave de la contraseña
            const key = await this.deriveKeyFromPassword(password, salt);

            // Cifrar la clave privada
            const encoder = new TextEncoder();
            const data = encoder.encode(privateKeyPEM);

            const ciphertext = await crypto.subtle.encrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                data
            );

            // Combinar salt:iv:ciphertext y codificar en base64
            const combined = new Uint8Array(salt.length + iv.length + ciphertext.byteLength);
            combined.set(salt, 0);
            combined.set(iv, salt.length);
            combined.set(new Uint8Array(ciphertext), salt.length + iv.length);

            return this.arrayBufferToBase64(combined);
        } catch (error) {
            // console.error('Error cifrando clave privada:', error);
            throw error;
        }
    },

    /**
     * Descifra la clave privada RSA usando la contraseña del usuario
     * Input: base64(salt:iv:ciphertext)
     */
    async decryptPrivateKeyWithPassword(encryptedData, password) {
        if (!this.isSecureContext) {
            throw new Error('Descifrado requiere contexto seguro (HTTPS)');
        }

        try {
            // Decodificar base64
            const combined = new Uint8Array(this.base64ToArrayBuffer(encryptedData));

            // Extraer salt, iv y ciphertext
            const salt = combined.slice(0, 16);
            const iv = combined.slice(16, 28);
            const ciphertext = combined.slice(28);

            // Derivar clave de la contraseña
            const key = await this.deriveKeyFromPassword(password, salt);

            // Descifrar
            const decrypted = await crypto.subtle.decrypt(
                { name: 'AES-GCM', iv: iv },
                key,
                ciphertext
            );

            // Convertir a string
            const decoder = new TextDecoder();
            return decoder.decode(decrypted);
        } catch (error) {
            // console.error('Error descifrando clave privada:', error);
            throw new Error('Contraseña incorrecta o datos corruptos');
        }
    },

    // ==================== FUNCIONES PARA GRUPOS ====================

    /**
     * Genera una clave AES para un grupo
     * @returns {Promise<Object>} { key: Uint8Array, keyHex: string, keyHash: string }
     */
    async generateGroupKey() {
        const key = this.generateRandomAESKey();
        const keyHex = Array.from(key).map(b => b.toString(16).padStart(2, '0')).join('');

        // Calcular hash SHA-256
        const keyHash = await this.hashSHA256(keyHex);

        this.log('generateGroupKey', {
            keyLength: key.length,
            keyHex: keyHex.substring(0, 32) + '...',
            keyHash: keyHash
        });

        return {
            key: key,
            keyHex: keyHex,
            keyHash: keyHash
        };
    },

    /**
     * Calcula el hash SHA-256 de un string
     */
    async hashSHA256(text) {
        // Implementación simple de SHA-256 usando Web Crypto API
        const encoder = new TextEncoder();
        const data = encoder.encode(text);

        const hash = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(hash))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    },

    /**
     * Encripta la clave AES del grupo con la clave pública RSA de un miembro
     * @param {string} groupKeyHex - Clave AES en hexadecimal
     * @param {string} publicKeyPem - Clave pública RSA en formato PEM
     * @returns {Promise<string>} Clave encriptada en base64
     */
    async encryptGroupKeyForMember(groupKeyHex, publicKeyPem) {
        try {
            this.log('encryptGroupKeyForMember', {
                groupKeyLength: groupKeyHex.length,
                publicKeyPem: publicKeyPem.substring(0, 100) + '...'
            });

            // Encriptar usando RSA
            const encrypted = await this.encryptRSA(groupKeyHex, publicKeyPem);

            this.log('encryptGroupKeyForMember - Result', {
                encryptedLength: encrypted.length,
                encrypted: encrypted.substring(0, 50) + '...'
            });

            return encrypted;
        } catch (error) {
            // console.error('Error encriptando clave de grupo:', error);
            throw error;
        }
    },

    /**
     * Desencripta la clave AES del grupo con la clave privada RSA del usuario
     * @param {string} encryptedGroupKey - Clave encriptada en base64
     * @param {string} privateKeyPem - Clave privada RSA en formato PEM
     * @returns {Promise<string>} Clave AES en hexadecimal
     */
    async decryptGroupKey(encryptedGroupKey, privateKeyPem) {
        try {
            this.log('decryptGroupKey', {
                encryptedLength: encryptedGroupKey.length
            });

            // Desencriptar usando RSA
            const decrypted = await this.decryptRSA(encryptedGroupKey, privateKeyPem);

            this.log('decryptGroupKey - Result', {
                decryptedLength: decrypted.length,
                decrypted: decrypted.substring(0, 32) + '...'
            });

            return decrypted;
        } catch (error) {
            // console.error('Error desencriptando clave de grupo:', error);
            throw error;
        }
    },

    /**
     * Convierte string hexadecimal a Uint8Array de forma segura para móviles
     */
    hexToBytes(hex) {
        if (!hex || hex.length % 2 !== 0) {
            throw new Error('Hex string inválido');
        }

        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            // Usar parseInt con base 16 de forma explícita y segura
            const byte = parseInt(hex.substr(i, 2), 16);
            if (isNaN(byte)) {
                throw new Error(`Byte inválido en posición ${i}: ${hex.substr(i, 2)}`);
            }
            bytes[i / 2] = byte;
        }
        return bytes;
    },

    /**
     * Encripta un mensaje de grupo con la clave AES del grupo
     * @param {string} message - Mensaje a encriptar
     * @param {string} groupKeyHex - Clave AES en hexadecimal
     * @returns {Promise<Object>} { encrypted_message, iv }
     */
    async encryptGroupMessage(message, groupKeyHex) {
        try {
            // Convertir hex a bytes usando método seguro para móviles
            const keyBytes = this.hexToBytes(groupKeyHex);

            // Generar IV
            const iv = this.generateIV();

            // Encriptar con AES
            const encrypted = await this.encryptAES(message, keyBytes, iv);

            this.log('encryptGroupMessage', {
                messageLength: message.length,
                encryptedLength: encrypted.length,
                iv: iv
            });

            return {
                encrypted_message: encrypted,
                iv: iv
            };
        } catch (error) {
            // console.error('Error encriptando mensaje de grupo:', error);
            throw error;
        }
    },

    /**
     * Desencripta un mensaje de grupo con la clave AES del grupo
     * @param {string} encryptedMessage - Mensaje encriptado en base64
     * @param {string} iv - Vector de inicialización en base64
     * @param {string} groupKeyHex - Clave AES en hexadecimal
     * @returns {Promise<string>} Mensaje desencriptado
     */
    async decryptGroupMessage(encryptedMessage, iv, groupKeyHex) {
        try {
            // Convertir hex a bytes usando método seguro para móviles
            const keyBytes = this.hexToBytes(groupKeyHex);

            // Desencriptar con AES
            const decrypted = await this.decryptAES(encryptedMessage, keyBytes, iv);

            this.log('decryptGroupMessage', {
                encryptedLength: encryptedMessage.length,
                decryptedLength: decrypted.length
            });

            return decrypted;
        } catch (error) {
            // console.error('Error desencriptando mensaje de grupo:', error);
            throw error;
        }
    },

    /**
     * Firma un mensaje de grupo con la clave privada RSA
     * @param {string} message - Mensaje a firmar
     * @param {string} privateKeyPem - Clave privada RSA en formato PEM
     * @returns {Promise<string>} Firma en base64
     */
    async signGroupMessage(message, privateKeyPem) {
        try {
            const signature = await this.signMessage(message, privateKeyPem);

            this.log('signGroupMessage', {
                messageLength: message.length,
                signatureLength: signature.length
            });

            return signature;
        } catch (error) {
            // console.error('Error firmando mensaje de grupo:', error);
            throw error;
        }
    },

    /**
     * Verifica la firma de un mensaje de grupo
     * @param {string} message - Mensaje original
     * @param {string} signature - Firma en base64
     * @param {string} publicKeyPem - Clave pública RSA del emisor
     * @returns {Promise<boolean>} true si la firma es válida
     */
    async verifyGroupMessageSignature(message, signature, publicKeyPem) {
        try {
            const isValid = await this.verifySignature(message, signature, publicKeyPem);

            this.log('verifyGroupMessageSignature', {
                isValid: isValid
            });

            return isValid;
        } catch (error) {
            // console.error('Error verificando firma de grupo:', error);
            return false;
        }
    }
};

export default CryptoModule;
