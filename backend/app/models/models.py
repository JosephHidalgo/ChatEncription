"""
Modelos de base de datos para el sistema de chat seguro.
Define las tablas de usuarios, mensajes, sesiones y auditoría.
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey, LargeBinary
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
from datetime import datetime


class User(Base):
    """
    Modelo de usuario del sistema.
    
    Políticas de Seguridad:
    - Contraseña hasheada con bcrypt
    - Clave privada RSA encriptada
    - Secreto TOTP para 2FA
    - Registro de intentos de login fallidos
    """
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    
    # Claves RSA
    public_key_rsa = Column(Text, nullable=False)  # Clave pública (PEM)
    encrypted_private_key_rsa = Column(LargeBinary, nullable=True)  # Clave privada cifrada
    
    # Autenticación de dos factores (TOTP)
    totp_secret = Column(String(255), nullable=True)
    totp_enabled = Column(Boolean, default=False)
    
    # Seguridad
    failed_login_attempts = Column(Integer, default=0)
    account_locked_until = Column(DateTime, nullable=True)
    last_password_change = Column(DateTime, default=func.now())
    
    # Rotación de claves
    key_rotation_date = Column(DateTime, default=func.now())
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    last_login = Column(DateTime, nullable=True)
    
    # Estado
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    
    # Relaciones
    sent_messages = relationship("Message", foreign_keys="Message.sender_id", back_populates="sender")
    received_messages = relationship("Message", foreign_keys="Message.recipient_id", back_populates="recipient")
    sessions = relationship("Session", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")


class Message(Base):
    """
    Modelo de mensajes cifrados.
    
    Almacena mensajes en formato cifrado con:
    - Contenido cifrado con AES-256-CBC
    - Firma digital para autenticidad
    - IV para el cifrado
    - Clave AES cifrada con RSA
    """
    __tablename__ = "messages"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Usuarios
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    recipient_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Contenido cifrado
    encrypted_content = Column(Text, nullable=False)  # Mensaje cifrado con AES
    encrypted_aes_key = Column(Text, nullable=True)  # Clave AES cifrada con RSA (puede ser null si usa clave de sesión)
    iv = Column(String(255), nullable=False)  # Vector de inicialización
    encrypted_data = Column(Text, nullable=True)  # JSON completo del sobre cifrado (para versión simplificada)
    
    # Seguridad
    signature = Column(Text, nullable=False)  # Firma digital RSA del emisor
    
    # Metadatos
    timestamp = Column(DateTime, default=func.now(), index=True)
    is_read = Column(Boolean, default=False)
    read_at = Column(DateTime, nullable=True)
    
    # Para prevenir replay attacks
    nonce = Column(String(64), unique=True, nullable=False)
    
    # Relaciones
    sender = relationship("User", foreign_keys=[sender_id], back_populates="sent_messages")
    recipient = relationship("User", foreign_keys=[recipient_id], back_populates="received_messages")


class Session(Base):
    """
    Modelo de sesiones activas.
    
    Rastrea sesiones JWT y claves de sesión AES temporales.
    Implementa rotación automática de claves.
    """
    __tablename__ = "sessions"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Tokens JWT
    access_token_jti = Column(String(255), unique=True, nullable=False, index=True)  # JWT ID
    refresh_token_jti = Column(String(255), unique=True, nullable=True, index=True)
    
    # Clave de sesión AES (para cifrado rápido en WebSocket)
    session_key_aes = Column(LargeBinary, nullable=True)
    session_key_created_at = Column(DateTime, default=func.now())
    
    # Información de conexión
    ip_address = Column(String(45), nullable=True)  # IPv4 o IPv6
    user_agent = Column(String(500), nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=func.now())
    expires_at = Column(DateTime, nullable=False)
    last_activity = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Estado
    is_active = Column(Boolean, default=True)
    revoked = Column(Boolean, default=False)
    revoked_at = Column(DateTime, nullable=True)
    
    # Relación
    user = relationship("User", back_populates="sessions")


class AuditLog(Base):
    """
    Modelo de logs de auditoría.
    
    Registra todas las acciones de seguridad críticas:
    - Intentos de login
    - Rotación de claves
    - Accesos no autorizados
    - Cambios de configuración
    """
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    
    # Acción
    action = Column(String(100), nullable=False, index=True)
    action_type = Column(String(50), nullable=False, index=True)  # LOGIN, LOGOUT, KEY_ROTATION, etc.
    
    # Detalles
    details = Column(Text, nullable=True)
    success = Column(Boolean, default=True)
    
    # Información de contexto
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(500), nullable=True)
    
    # Timestamp
    timestamp = Column(DateTime, default=func.now(), index=True)
    
    # Relación
    user = relationship("User", back_populates="audit_logs")


class KeyRotationHistory(Base):
    """
    Modelo de historial de rotación de claves.
    
    Mantiene registro de todas las rotaciones de claves RSA
    para cumplir con políticas de seguridad.
    """
    __tablename__ = "key_rotation_history"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Hash de claves (para verificación, no las claves completas)
    old_public_key_hash = Column(String(64), nullable=False)
    new_public_key_hash = Column(String(64), nullable=False)
    
    # Información
    rotation_reason = Column(String(255), nullable=True)
    rotated_at = Column(DateTime, default=func.now())
    
    # Relación implícita con User
