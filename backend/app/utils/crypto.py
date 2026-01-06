"""
Módulo de criptografía para cifrado híbrido (RSA + AES).
Implementa cifrado asimétrico, simétrico, firmas digitales y gestión de claves.

Políticas de Seguridad Implementadas:
- Cifrado RSA-2048/4096 para intercambio de claves
- Cifrado AES-256-CBC para mensajes
- Firmas digitales RSA-PSS para autenticidad
- Generación de claves criptográficamente seguras
- Protección contra ataques de padding (OAEP, PSS)
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import secrets
import os
from typing import Tuple, Dict
from base64 import b64encode, b64decode
from datetime import datetime
from app.core.config import settings


class CryptoManager:
    """
    Gestor de operaciones criptográficas para el sistema de chat seguro.
    Maneja cifrado híbrido RSA + AES según las mejores prácticas.
    """
    
    def __init__(self):
        """Inicializa el gestor de criptografía"""
        self.backend = default_backend()
        self.rsa_key_size = settings.RSA_KEY_SIZE
        self.aes_key_size = settings.AES_KEY_SIZE // 8  # Convertir bits a bytes
    
    # ===================== CIFRADO ASIMÉTRICO (RSA) =====================
    
    def generate_rsa_key_pair(self) -> Tuple[bytes, bytes]:
        """
        Genera un par de claves RSA (pública y privada).
        
        Políticas de Seguridad:
        - Usa el tamaño de clave configurado (mínimo 2048 bits)
        - Exponente público estándar (65537)
        - Generación con fuente criptográficamente segura
        
        Returns:
            Tupla (clave_privada_pem, clave_pública_pem)
        """
        # Generar par de claves RSA
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.rsa_key_size,
            backend=self.backend
        )
        
        public_key = private_key.public_key()
        
        # Serializar clave privada a formato PEM (con encriptación opcional)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()  # Sin password aquí
        )
        
        # Serializar clave pública a formato PEM
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def encrypt_with_public_key(self, public_key_pem: bytes, data: bytes) -> bytes:
        """
        Cifra datos usando una clave pública RSA.
        Usa OAEP con SHA-256 para protección contra ataques de padding.
        
        Args:
            public_key_pem: Clave pública en formato PEM
            data: Datos a cifrar (máximo 190 bytes para RSA-2048)
        
        Returns:
            Datos cifrados
        """
        # Cargar clave pública
        public_key = serialization.load_pem_public_key(
            public_key_pem,
            backend=self.backend
        )
        
        # Cifrar con OAEP (Optimal Asymmetric Encryption Padding)
        encrypted_data = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return encrypted_data
    
    def decrypt_with_private_key(self, private_key_pem: bytes, encrypted_data: bytes) -> bytes:
        """
        Descifra datos usando una clave privada RSA.
        
        Args:
            private_key_pem: Clave privada en formato PEM
            encrypted_data: Datos cifrados
        
        Returns:
            Datos descifrados
        """
        # Cargar clave privada
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=self.backend
        )
        
        # Descifrar
        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return decrypted_data
    
    # ===================== FIRMAS DIGITALES (RSA-PSS) =====================
    
    def sign_message(self, private_key_pem: bytes, message: bytes) -> bytes:
        """
        Firma un mensaje usando RSA-PSS para garantizar autenticidad e integridad.
        
        Args:
            private_key_pem: Clave privada en formato PEM
            message: Mensaje a firmar
        
        Returns:
            Firma digital
        """
        # Cargar clave privada
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=None,
            backend=self.backend
        )
        
        # Crear firma con PSS (Probabilistic Signature Scheme)
        signature = private_key.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature
    
    def verify_signature(self, public_key_pem: bytes, message: bytes, signature: bytes) -> bool:
        """
        Verifica una firma digital.
        
        Args:
            public_key_pem: Clave pública en formato PEM
            message: Mensaje original
            signature: Firma a verificar
        
        Returns:
            True si la firma es válida, False en caso contrario
        """
        try:
            # Cargar clave pública
            public_key = serialization.load_pem_public_key(
                public_key_pem,
                backend=self.backend
            )
            
            # Verificar firma
            public_key.verify(
                signature,
                message,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
    
    # ===================== CIFRADO SIMÉTRICO (AES-256-CBC) =====================
    
    def generate_aes_key(self) -> bytes:
        """
        Genera una clave AES-256 criptográficamente segura.
        
        Returns:
            Clave AES de 256 bits (32 bytes)
        """
        return secrets.token_bytes(self.aes_key_size)
    
    def generate_iv(self) -> bytes:
        """
        Genera un Vector de Inicialización (IV) aleatorio para AES-CBC.
        
        Returns:
            IV de 128 bits (16 bytes)
        """
        return os.urandom(16)
    
    def encrypt_aes_cbc(self, key: bytes, plaintext: bytes) -> Dict[str, str]:
        """
        Cifra datos usando AES-256-CBC.
        
        Políticas de Seguridad:
        - Modo CBC para seguridad adicional
        - IV único para cada mensaje
        - PKCS7 padding automático
        
        Args:
            key: Clave AES de 256 bits
            plaintext: Datos a cifrar
        
        Returns:
            Diccionario con 'ciphertext' e 'iv' en base64
        """
        # Generar IV único
        iv = self.generate_iv()
        
        # Crear cifrador AES-CBC
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        
        encryptor = cipher.encryptor()
        
        # Aplicar padding PKCS7 manualmente
        padded_plaintext = self._pad_pkcs7(plaintext)
        
        # Cifrar
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        return {
            'ciphertext': b64encode(ciphertext).decode('utf-8'),
            'iv': b64encode(iv).decode('utf-8')
        }
    
    def decrypt_aes_cbc(self, key: bytes, ciphertext_b64: str, iv_b64: str) -> bytes:
        """
        Descifra datos usando AES-256-CBC.
        
        Args:
            key: Clave AES de 256 bits
            ciphertext_b64: Texto cifrado en base64
            iv_b64: Vector de inicialización en base64
        
        Returns:
            Datos descifrados
        """
        # Decodificar de base64
        ciphertext = b64decode(ciphertext_b64)
        iv = b64decode(iv_b64)
        
        # Crear descifrador AES-CBC
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=self.backend
        )
        
        decryptor = cipher.decryptor()
        
        # Descifrar
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remover padding PKCS7
        plaintext = self._unpad_pkcs7(padded_plaintext)
        
        return plaintext
    
    # ===================== UTILIDADES =====================
    
    def _pad_pkcs7(self, data: bytes) -> bytes:
        """
        Aplica padding PKCS7 a los datos.
        
        Args:
            data: Datos sin padding
        
        Returns:
            Datos con padding PKCS7
        """
        pad_length = 16 - (len(data) % 16)
        return data + bytes([pad_length] * pad_length)
    
    def _unpad_pkcs7(self, data: bytes) -> bytes:
        """
        Remueve padding PKCS7 de los datos.
        
        Args:
            data: Datos con padding
        
        Returns:
            Datos sin padding
        """
        pad_length = data[-1]
        return data[:-pad_length]
    
    def create_secure_message_envelope(
        self,
        message: str,
        sender_private_key: bytes,
        recipient_public_key: bytes
    ) -> Dict[str, str]:
        """
        Crea un sobre seguro para un mensaje usando cifrado híbrido.
        
        Flujo:
        1. Genera clave AES temporal
        2. Cifra el mensaje con AES-CBC
        3. Cifra la clave AES con la clave pública del destinatario (RSA)
        4. Firma el mensaje con la clave privada del emisor
        
        Args:
            message: Mensaje en texto plano
            sender_private_key: Clave privada del emisor (para firma)
            recipient_public_key: Clave pública del destinatario (para cifrado)
        
        Returns:
            Diccionario con mensaje cifrado, clave AES cifrada, IV y firma
        """
        message_bytes = message.encode('utf-8')
        
        # 1. Generar clave AES temporal
        aes_key = self.generate_aes_key()
        
        # 2. Cifrar mensaje con AES
        encrypted_message = self.encrypt_aes_cbc(aes_key, message_bytes)
        
        # 3. Cifrar clave AES con clave pública del destinatario
        encrypted_aes_key = self.encrypt_with_public_key(recipient_public_key, aes_key)
        
        # 4. Firmar el mensaje original
        signature = self.sign_message(sender_private_key, message_bytes)
        
        # 5. Crear sobre completo
        envelope = {
            'encrypted_message': encrypted_message['ciphertext'],
            'iv': encrypted_message['iv'],
            'encrypted_key': b64encode(encrypted_aes_key).decode('utf-8'),
            'signature': b64encode(signature).decode('utf-8'),
            'timestamp': datetime.utcnow().isoformat()
        }
        
        return envelope
    
    def open_secure_message_envelope(
        self,
        envelope: Dict[str, str],
        recipient_private_key: bytes,
        sender_public_key: bytes
    ) -> Tuple[str, bool]:
        """
        Abre un sobre seguro y verifica la autenticidad.
        
        Args:
            envelope: Sobre con mensaje cifrado
            recipient_private_key: Clave privada del destinatario (para descifrar)
            sender_public_key: Clave pública del emisor (para verificar firma)
        
        Returns:
            Tupla (mensaje_descifrado, firma_válida)
        """
        # 1. Descifrar clave AES con clave privada del destinatario
        encrypted_aes_key = b64decode(envelope['encrypted_key'])
        aes_key = self.decrypt_with_private_key(recipient_private_key, encrypted_aes_key)
        
        # 2. Descifrar mensaje con AES
        decrypted_message_bytes = self.decrypt_aes_cbc(
            aes_key,
            envelope['encrypted_message'],
            envelope['iv']
        )
        
        # 3. Verificar firma digital
        signature = b64decode(envelope['signature'])
        signature_valid = self.verify_signature(
            sender_public_key,
            decrypted_message_bytes,
            signature
        )
        
        # 4. Decodificar mensaje
        message = decrypted_message_bytes.decode('utf-8')
        
        return message, signature_valid


# Instancia global del gestor de criptografía
crypto_manager = CryptoManager()
