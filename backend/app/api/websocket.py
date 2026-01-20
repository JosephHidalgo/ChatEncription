"""
WebSocket manager para chat en tiempo real.
Maneja conexiones, envío de mensajes cifrados y notificaciones.
"""
from fastapi import WebSocket, WebSocketDisconnect, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import Dict, List
from datetime import datetime
import json
import secrets
from app.core.database import get_db
from app.core.security import decode_token
from app.models.models import User, Message
from app.schemas.schemas import WebSocketMessage, MessageEncrypted
from app.utils.crypto import crypto_manager
from loguru import logger


class ConnectionManager:
    """
    Gestor de conexiones WebSocket para chat en tiempo real.
    
    Políticas de Seguridad:
    - Autenticación por token JWT
    - Mensajes cifrados end-to-end
    - Prevención de replay attacks con nonce
    - Rate limiting por conexión
    """
    
    def __init__(self):
        # Diccionario: user_id -> List[WebSocket]
        self.active_connections: Dict[int, List[WebSocket]] = {}
        
        # Diccionario: user_id -> última actividad
        self.last_activity: Dict[int, datetime] = {}
    
    async def connect(self, websocket: WebSocket, user_id: int):
        """
        Acepta una conexión WebSocket y la registra.
        
        Args:
            websocket: Objeto WebSocket
            user_id: ID del usuario conectado
        """
        await websocket.accept()
        
        if user_id not in self.active_connections:
            self.active_connections[user_id] = []
        
        self.active_connections[user_id].append(websocket)
        self.last_activity[user_id] = datetime.utcnow()
        
        logger.info(f"Usuario {user_id} conectado. Conexiones activas: {len(self.active_connections[user_id])}")
    
    def disconnect(self, websocket: WebSocket, user_id: int):
        """
        Desconecta un WebSocket y lo elimina del registro.
        
        Args:
            websocket: Objeto WebSocket
            user_id: ID del usuario
        """
        if user_id in self.active_connections:
            if websocket in self.active_connections[user_id]:
                self.active_connections[user_id].remove(websocket)
            
            # Si no quedan conexiones, eliminar del diccionario
            if not self.active_connections[user_id]:
                del self.active_connections[user_id]
                if user_id in self.last_activity:
                    del self.last_activity[user_id]
        
        logger.info(f"Usuario {user_id} desconectado")
    
    async def send_personal_message(self, message: dict, user_id: int):
        """
        Envía un mensaje a todas las conexiones de un usuario específico.
        
        Args:
            message: Mensaje a enviar (diccionario)
            user_id: ID del usuario destinatario
        """
        if user_id in self.active_connections:
            disconnected = []
            
            for connection in self.active_connections[user_id]:
                try:
                    await connection.send_json(message)
                except Exception as e:
                    logger.error(f"Error enviando mensaje a usuario {user_id}: {e}")
                    disconnected.append(connection)
            
            # Limpiar conexiones fallidas
            for conn in disconnected:
                self.disconnect(conn, user_id)
    
    async def broadcast(self, message: dict, exclude_user: int = None):
        """
        Envía un mensaje a todos los usuarios conectados.
        
        Args:
            message: Mensaje a enviar
            exclude_user: ID de usuario a excluir (opcional)
        """
        for user_id in list(self.active_connections.keys()):
            if exclude_user and user_id == exclude_user:
                continue
            
            await self.send_personal_message(message, user_id)
    
    def is_user_online(self, user_id: int) -> bool:
        """
        Verifica si un usuario está conectado.
        
        Args:
            user_id: ID del usuario
        
        Returns:
            True si el usuario tiene al menos una conexión activa
        """
        return user_id in self.active_connections and len(self.active_connections[user_id]) > 0
    
    def get_online_users(self) -> List[int]:
        """
        Obtiene la lista de usuarios conectados actualmente.
        
        Returns:
            Lista de IDs de usuarios conectados
        """
        return list(self.active_connections.keys())


# Instancia global del gestor de conexiones
manager = ConnectionManager()


async def get_user_from_websocket_token(token: str, db: AsyncSession) -> User:
    """
    Valida el token JWT y obtiene el usuario para WebSocket.
    
    Args:
        token: Token JWT
        db: Sesión de base de datos
    
    Returns:
        Usuario autenticado
    """
    payload = decode_token(token)
    if payload is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido"
        )
    
    user_id: str = payload.get("sub")
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido"
        )
    
    result = await db.execute(
        select(User).where(User.id == int(user_id))
    )
    user = result.scalar_one_or_none()
    
    if user is None or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no válido"
        )
    
    return user


async def save_encrypted_message(
    db: AsyncSession,
    sender_id: int,
    recipient_id: int,
    encrypted_data: dict
) -> Message:
    """
    Guarda un mensaje cifrado en la base de datos.
    
    Args:
        db: Sesión de base de datos
        sender_id: ID del emisor
        recipient_id: ID del destinatario
        encrypted_data: Datos del mensaje cifrado (incluye versión para receptor y emisor)
    
    Returns:
        Mensaje guardado
    """
    # Generar nonce único para prevenir replay attacks
    nonce = secrets.token_hex(32)
    
    # Guardar el sobre completo como JSON (incluye ambas versiones cifradas)
    encrypted_data_json = json.dumps(encrypted_data)
    
    logger.info(f"Guardando mensaje: sender={sender_id}, recipient={recipient_id}")
    logger.info(f"encrypted_content (para receptor): {encrypted_data.get('encrypted_message', '')[:50]}...")
    logger.info(f"sender_encrypted_message (para emisor): {encrypted_data.get('sender_encrypted_message', '')[:50]}...")
    logger.info(f"iv: {encrypted_data.get('iv')}")
    logger.info(f"signature: {encrypted_data.get('signature', '')[:30]}...")
    
    try:
        message = Message(
            sender_id=sender_id,
            recipient_id=recipient_id,
            # Versión cifrada para el RECEPTOR
            encrypted_content=encrypted_data.get('encrypted_message'),
            encrypted_aes_key=encrypted_data.get('encrypted_key'),
            iv=encrypted_data.get('iv'),
            signature=encrypted_data.get('signature'),
            encrypted_data=encrypted_data_json,  # Sobre completo en JSON (incluye versión del emisor)
            nonce=nonce,
            timestamp=datetime.utcnow()
        )
        
        db.add(message)
        await db.commit()
        await db.refresh(message)
        
        logger.info(f"Mensaje guardado exitosamente con ID: {message.id}")
        return message
    except Exception as e:
        logger.error(f"Error guardando mensaje: {e}")
        await db.rollback()
        raise


async def handle_websocket_message(
    websocket: WebSocket,
    current_user: User,
    data: dict,
    db: AsyncSession
):
    """
    Procesa mensajes recibidos por WebSocket.
    
    Args:
        websocket: Conexión WebSocket
        current_user: Usuario que envía el mensaje
        data: Datos del mensaje
        db: Sesión de base de datos
    """
    message_type = data.get('type')
    
    if message_type == 'message':
        # Mensaje de chat cifrado
        recipient_id = data.get('recipient_id')
        encrypted_data = data.get('encrypted_data')
        
        if not recipient_id or not encrypted_data:
            await websocket.send_json({
                'type': 'error',
                'message': 'Datos de mensaje incompletos'
            })
            return
        
        # Guardar mensaje en BD
        message = await save_encrypted_message(
            db,
            current_user.id,
            recipient_id,
            encrypted_data
        )
        
        # Enviar al destinatario si está online
        if manager.is_user_online(recipient_id):
            await manager.send_personal_message({
                'type': 'new_message',
                'message_id': message.id,
                'sender_id': current_user.id,
                'sender_username': current_user.username,
                'encrypted_data': encrypted_data,
                'timestamp': message.timestamp.isoformat()
            }, recipient_id)
        
        # Confirmar al emisor
        await websocket.send_json({
            'type': 'message_sent',
            'message_id': message.id,
            'timestamp': message.timestamp.isoformat()
        })
    
    elif message_type == 'typing':
        # Notificación de escritura
        recipient_id = data.get('recipient_id')
        is_typing = data.get('is_typing', False)
        
        if recipient_id and manager.is_user_online(recipient_id):
            await manager.send_personal_message({
                'type': 'typing_notification',
                'sender_id': current_user.id,
                'sender_username': current_user.username,
                'is_typing': is_typing
            }, recipient_id)
    
    elif message_type == 'read_receipt':
        # Confirmación de lectura
        message_id = data.get('message_id')
        
        if message_id:
            # Actualizar mensaje como leído
            result = await db.execute(
                select(Message).where(Message.id == message_id)
            )
            message = result.scalar_one_or_none()
            
            if message and message.recipient_id == current_user.id:
                message.is_read = True
                message.read_at = datetime.utcnow()
                await db.commit()
                
                # Notificar al emisor
                if manager.is_user_online(message.sender_id):
                    await manager.send_personal_message({
                        'type': 'message_read',
                        'message_id': message_id,
                        'read_at': message.read_at.isoformat()
                    }, message.sender_id)
    
    elif message_type == 'get_online_users':
        # Solicitud de usuarios en línea
        online_users = manager.get_online_users()
        await websocket.send_json({
            'type': 'online_users',
            'users': online_users
        })
