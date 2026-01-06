"""
Endpoints de API REST para autenticación y usuarios.
"""
import json
from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.core.database import get_db
from app.core.security import decode_token
from app.schemas.schemas import (
    UserCreate,
    UserResponse,
    UserLogin,
    Token,
    TOTPSetupResponse,
    TOTPEnable,
    UserPublicKey
)
from app.services.auth_service import AuthService
from app.models.models import User, Message
from sqlalchemy import select, or_, and_
from typing import List

router = APIRouter(prefix="/auth", tags=["Autenticación"])

# OAuth2 scheme para extracción de tokens
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# Rate limiter
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
        # Buscar mensajes entre los dos usuarios
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
            # Si tenemos encrypted_data como JSON, parsearlo
            encrypted_data = None
            if msg.encrypted_data:
                try:
                    encrypted_data = json.loads(msg.encrypted_data)
                except:
                    # Si no es JSON válido, construir el sobre manualmente
                    encrypted_data = {
                        "encrypted_message": msg.encrypted_content,
                        "iv": msg.iv,
                        "signature": msg.signature
                    }
            else:
                # Construir sobre desde campos individuales
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
