"""
Endpoints de API REST para autenticación y usuarios.
"""
import json
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address
from datetime import datetime
from app.core.database import get_db
from app.core.security import decode_token, verify_password
from app.schemas.schemas import (
    UserCreate,
    UserResponse,
    UserLogin,
    Token,
    TOTPSetupResponse,
    TOTPEnable,
    UserPublicKey,
    KeyRotationRequest,
    KeyRotationResponse
)
from app.services.auth_service import AuthService
from app.models.models import User, Message
from app.core.config import settings
from sqlalchemy import select, or_, and_
from typing import List

router = APIRouter(prefix="/auth", tags=["Autenticación"])

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

limiter = Limiter(key_func=get_remote_address)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db)
) -> User:
    """
    Dependency para obtener el usuario actual desde el token JWT.
    
    Args:
        token: Token JWT del header Authorization
        db: Sesión de base de datos
    
    Returns:
        Usuario autenticado
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="No se pudo validar las credenciales",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Decodificar token
    payload = decode_token(token)
    if payload is None:
        raise credentials_exception
    
    user_id: str = payload.get("sub")
    if user_id is None:
        raise credentials_exception
    
    # Buscar usuario
    result = await db.execute(
        select(User).where(User.id == int(user_id))
    )
    user = result.scalar_one_or_none()
    
    if user is None:
        raise credentials_exception
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuario inactivo"
        )
    
    return user


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(
    user_data: UserCreate,
    request: Request,
    db: AsyncSession = Depends(get_db)
):
    """
    Registra un nuevo usuario en el sistema.
    
    Políticas:
    - Genera automáticamente par de claves RSA
    - Valida fortaleza de contraseña
    - Audita el registro
    """
    auth_service = AuthService(db)
    ip_address = request.client.host
    
    user = await auth_service.register_user(user_data, ip_address)
    
    return user


@router.post("/login", response_model=Token)
@limiter.limit("5/15minute")
async def login(
    request: Request,
    login_data: UserLogin,
    db: AsyncSession = Depends(get_db)
):
    """
    Autentica un usuario y devuelve tokens JWT.
    
    Políticas:
    - Rate limiting: 5 intentos cada 15 minutos
    - Bloqueo de cuenta tras 5 intentos fallidos
    - Requiere 2FA si está habilitado
    """
    auth_service = AuthService(db)
    ip_address = request.client.host
    user_agent = request.headers.get("user-agent", "Unknown")
    
    user, tokens = await auth_service.authenticate_user(
        login_data,
        ip_address,
        user_agent
    )
    
    return tokens


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user)
):
    """
    Obtiene información del usuario autenticado actual.
    """
    return current_user


@router.post("/totp/setup", response_model=TOTPSetupResponse)
async def setup_totp(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Configura autenticación de dos factores (TOTP).
    
    Devuelve:
    - Secreto TOTP
    - URL para código QR
    - Códigos de respaldo
    """
    auth_service = AuthService(db)
    return await auth_service.setup_totp(current_user.id)


@router.post("/totp/enable")
async def enable_totp(
    totp_data: TOTPEnable,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Habilita 2FA tras verificar el código TOTP.
    """
    auth_service = AuthService(db)
    success = await auth_service.enable_totp(
        current_user.id,
        totp_data.totp_code,
        totp_data.password
    )
    
    return {"message": "2FA habilitado exitosamente", "success": success}


@router.get("/users/public-key/{user_id}", response_model=UserPublicKey)
async def get_user_public_key(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Obtiene la clave pública RSA de un usuario.
    Necesaria para cifrar mensajes destinados a ese usuario.
    """
    result = await db.execute(
        select(User).where(User.id == user_id)
    )
    user = result.scalar_one_or_none()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuario no encontrado"
        )
    
    return UserPublicKey(
        user_id=user.id,
        username=user.username,
        public_key_rsa=user.public_key_rsa
    )


@router.get("/me/private-key")
async def get_my_private_key(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Obtiene la clave privada RSA del usuario actual.
    
    IMPORTANTE: 
    - Solo debe llamarse una vez al iniciar sesión
    - La clave debe guardarse de forma segura en el cliente
    - Esta clave es necesaria para descifrar mensajes recibidos
    
    Returns:
        Clave privada RSA en formato PEM
    """
    if not current_user.encrypted_private_key_rsa:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Clave privada no disponible. Contacte al administrador."
        )
    
    # Decodificar la clave privada
    try:
        private_key_pem = current_user.encrypted_private_key_rsa.decode('utf-8')
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al decodificar la clave privada"
        )
    
    return {
        "private_key_rsa": private_key_pem,
        "user_id": current_user.id
    }


@router.get("/users", response_model=List[UserResponse])
async def list_users(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Lista todos los usuarios activos del sistema.
    """
    result = await db.execute(
        select(User).where(User.is_active == True)
    )
    users = result.scalars().all()
    
    return users


@router.get("/messages/history/{recipient_id}")
async def get_message_history(
    recipient_id: int,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Obtiene el historial de mensajes entre el usuario actual y otro usuario.
    
    Args:
        recipient_id: ID del otro usuario
        limit: Número máximo de mensajes a devolver (default 50)
    
    Returns:
        Lista de mensajes ordenados por fecha
    """
    try:
        result = await db.execute(
            select(Message)
            .where(
                or_(
                    and_(Message.sender_id == current_user.id, Message.recipient_id == recipient_id),
                    and_(Message.sender_id == recipient_id, Message.recipient_id == current_user.id)
                )
            )
            .order_by(Message.timestamp.desc())
            .limit(limit)
        )
        messages = result.scalars().all()
        
        # Revertir para que los más antiguos estén primero
        messages = list(reversed(messages))
        
        # Devolver los mensajes con el sobre cifrado parseado
        result_messages = []
        for msg in messages:
            encrypted_data = None
            if msg.encrypted_data:
                try:
                    encrypted_data = json.loads(msg.encrypted_data)
                except:
                    encrypted_data = {
                        "encrypted_message": msg.encrypted_content,
                        "iv": msg.iv,
                        "signature": msg.signature
                    }
            else:
                encrypted_data = {
                    "encrypted_message": msg.encrypted_content,
                    "iv": msg.iv,
                    "signature": msg.signature
                }
            
            result_messages.append({
                "id": msg.id,
                "sender_id": msg.sender_id,
                "recipient_id": msg.recipient_id,
                "encrypted_data": encrypted_data,
                "timestamp": msg.timestamp.isoformat(),
                "is_read": msg.is_read
            })
        
        return result_messages
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener historial de mensajes: {str(e)}"
        )


# ===================== ROTACIÓN DE CLAVES =====================

@router.post("/keys/rotate", response_model=KeyRotationResponse)
async def rotate_keys(
    rotation_request: KeyRotationRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Rota las claves RSA del usuario actual.
    
    Políticas de Seguridad:
    - Genera nuevo par de claves RSA-2048/4096
    - Registra la rotación en el historial
    - Audita la operación
    - Requiere confirmación con contraseña
    
    Args:
        rotation_request: Razón de la rotación y contraseña
    
    Returns:
        Nuevas claves públicas y privadas
    """
    auth_service = AuthService(db)
    
    # Verificar contraseña del usuario para confirmar la rotación
    if not verify_password(rotation_request.password, current_user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Contraseña incorrecta"
        )
    
    ip_address = request.client.host
    
    # Rotar claves
    rotation_result = await auth_service.rotate_user_keys(
        user_id=current_user.id,
        reason=rotation_request.reason,
        ip_address=ip_address
    )
    
    return rotation_result


@router.get("/keys/rotation-history")
async def get_rotation_history(
    limit: int = 10,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Obtiene el historial de rotaciones de claves del usuario actual.
    
    Args:
        limit: Número máximo de registros a devolver (default 10)
    
    Returns:
        Lista de rotaciones ordenadas por fecha
    """
    auth_service = AuthService(db)
    history = await auth_service.get_rotation_history(current_user.id, limit)
    
    return [
        {
            "id": h.id,
            "rotated_at": h.rotated_at,
            "rotation_reason": h.rotation_reason,
            "old_public_key": h.old_public_key[:50] + "...",
            "new_public_key": h.new_public_key[:50] + "..."
        }
        for h in history
    ]


@router.get("/keys/check-expiration")
async def check_key_expiration(
    current_user: User = Depends(get_current_user)
):
    """
    Verifica si las claves del usuario actual están próximas a vencer.
    
    Returns:
        Información sobre el estado de vencimiento de las claves
    """
    days_since_rotation = (datetime.utcnow() - current_user.key_rotation_date).days
    days_until_expiration = settings.KEY_ROTATION_DAYS - days_since_rotation
    
    is_expired = days_until_expiration <= 0
    is_expiring_soon = days_until_expiration <= 7 and not is_expired
    
    return {
        "user_id": current_user.id,
        "last_rotation": current_user.key_rotation_date,
        "days_since_rotation": days_since_rotation,
        "days_until_expiration": days_until_expiration,
        "rotation_policy_days": settings.KEY_ROTATION_DAYS,
        "is_expired": is_expired,
        "is_expiring_soon": is_expiring_soon,
        "message": (
            "¡Claves vencidas! Rota tus claves inmediatamente." if is_expired
            else f"Claves próximas a vencer en {days_until_expiration} días." if is_expiring_soon
            else f"Claves vigentes. Próxima rotación en {days_until_expiration} días."
        )
    }
