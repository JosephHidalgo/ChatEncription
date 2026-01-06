"""
Servicio de autenticación y gestión de usuarios.
Maneja registro, login, 2FA, sesiones y auditoría.
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status
from datetime import datetime, timedelta
from typing import Optional, Tuple
import secrets
import pyotp
from app.models.models import User, Session, AuditLog
from app.schemas.schemas import UserCreate, UserLogin, Token, TOTPSetupResponse
from app.core.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_totp_secret
)
from app.utils.crypto import crypto_manager
from app.core.config import settings


class AuthService:
    """Servicio de autenticación con políticas de seguridad"""
    
    def __init__(self, db: AsyncSession):
        self.db = db
    
    async def register_user(self, user_data: UserCreate, ip_address: str) -> User:
        """
        Registra un nuevo usuario en el sistema.
        
        Políticas de Seguridad:
        - Genera par de claves RSA automáticamente
        - Hash de contraseña con bcrypt
        - Registro en auditoría
        
        Args:
            user_data: Datos del usuario
            ip_address: IP del cliente
        
        Returns:
            Usuario creado
        """
        # Verificar si el usuario ya existe
        result = await self.db.execute(
            select(User).where(
                (User.username == user_data.username) | (User.email == user_data.email)
            )
        )
        existing_user = result.scalar_one_or_none()
        
        if existing_user:
            if existing_user.username == user_data.username:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="El nombre de usuario ya está en uso"
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="El email ya está registrado"
                )
        
        # Hash de la contraseña
        password_hash = get_password_hash(user_data.password)
        
        # Generar par de claves RSA
        private_key_pem, public_key_pem = crypto_manager.generate_rsa_key_pair()
        
        # Crear usuario
        new_user = User(
            username=user_data.username,
            email=user_data.email,
            password_hash=password_hash,
            public_key_rsa=public_key_pem.decode('utf-8'),
            # La clave privada se devuelve al cliente, NO se almacena sin cifrar
            totp_secret=generate_totp_secret(),
            totp_enabled=False
        )
        
        self.db.add(new_user)
        await self.db.commit()
        await self.db.refresh(new_user)
        
        # Log de auditoría
        await self._create_audit_log(
            user_id=new_user.id,
            action="Usuario registrado",
            action_type="REGISTER",
            ip_address=ip_address,
            success=True
        )
        
        # Devolver la clave privada para que el cliente la guarde
        # En producción, esto debería cifrarse con la contraseña del usuario
        new_user.encrypted_private_key_rsa = private_key_pem
        
        return new_user
    
    async def authenticate_user(
        self,
        login_data: UserLogin,
        ip_address: str,
        user_agent: str
    ) -> Tuple[User, Token]:
        """
        Autentica un usuario y crea tokens JWT.
        
        Políticas de Seguridad:
        - Bloqueo de cuenta tras 5 intentos fallidos
        - Verificación de 2FA si está habilitado
        - Rate limiting (implementado en endpoint)
        
        Args:
            login_data: Datos de login
            ip_address: IP del cliente
            user_agent: User agent del navegador
        
        Returns:
            Tupla (usuario, tokens)
        """
        # Buscar usuario
        result = await self.db.execute(
            select(User).where(User.username == login_data.username)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            await self._create_audit_log(
                user_id=None,
                action=f"Intento de login fallido: usuario '{login_data.username}' no encontrado",
                action_type="LOGIN_FAILED",
                ip_address=ip_address,
                success=False
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales incorrectas"
            )
        
        # Verificar si la cuenta está bloqueada
        if user.account_locked_until and user.account_locked_until > datetime.utcnow():
            await self._create_audit_log(
                user_id=user.id,
                action="Intento de acceso a cuenta bloqueada",
                action_type="LOGIN_BLOCKED",
                ip_address=ip_address,
                success=False
            )
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail=f"Cuenta bloqueada hasta {user.account_locked_until}"
            )
        
        # Verificar contraseña
        if not verify_password(login_data.password, user.password_hash):
            # Incrementar intentos fallidos
            user.failed_login_attempts += 1
            
            # Bloquear cuenta si supera el límite
            if user.failed_login_attempts >= 5:
                user.account_locked_until = datetime.utcnow() + timedelta(minutes=15)
                await self._create_audit_log(
                    user_id=user.id,
                    action="Cuenta bloqueada por múltiples intentos fallidos",
                    action_type="ACCOUNT_LOCKED",
                    ip_address=ip_address,
                    success=False
                )
            
            await self.db.commit()
            
            await self._create_audit_log(
                user_id=user.id,
                action="Contraseña incorrecta",
                action_type="LOGIN_FAILED",
                ip_address=ip_address,
                success=False
            )
            
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales incorrectas"
            )
        
        # Verificar 2FA si está habilitado
        if user.totp_enabled:
            if not login_data.totp_code:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Se requiere código 2FA"
                )
            
            if not self._verify_totp(user.totp_secret, login_data.totp_code):
                await self._create_audit_log(
                    user_id=user.id,
                    action="Código 2FA incorrecto",
                    action_type="LOGIN_FAILED_2FA",
                    ip_address=ip_address,
                    success=False
                )
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Código 2FA incorrecto"
                )
        
        # Login exitoso: resetear intentos fallidos
        user.failed_login_attempts = 0
        user.account_locked_until = None
        user.last_login = datetime.utcnow()
        
        # Crear tokens JWT
        access_token_jti = secrets.token_urlsafe(32)
        refresh_token_jti = secrets.token_urlsafe(32)
        
        access_token = create_access_token(
            data={"sub": str(user.id), "username": user.username, "jti": access_token_jti}
        )
        refresh_token = create_refresh_token(
            data={"sub": str(user.id), "jti": refresh_token_jti}
        )
        
        # Crear sesión
        session = Session(
            user_id=user.id,
            access_token_jti=access_token_jti,
            refresh_token_jti=refresh_token_jti,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        )
        
        self.db.add(session)
        await self.db.commit()
        
        # Log de auditoría
        await self._create_audit_log(
            user_id=user.id,
            action="Login exitoso",
            action_type="LOGIN_SUCCESS",
            ip_address=ip_address,
            success=True
        )
        
        tokens = Token(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer"
        )
        
        return user, tokens
    
    async def setup_totp(self, user_id: int) -> TOTPSetupResponse:
        """
        Configura TOTP (2FA) para un usuario.
        
        Args:
            user_id: ID del usuario
        
        Returns:
            Información para configurar 2FA (secreto, QR, códigos de respaldo)
        """
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado"
            )
        
        # Generar nuevo secreto TOTP
        secret = pyotp.random_base32()
        user.totp_secret = secret
        await self.db.commit()
        
        # Generar URL para QR code
        totp = pyotp.TOTP(secret)
        qr_url = totp.provisioning_uri(
            name=user.email,
            issuer_name=settings.APP_NAME
        )
        
        # Generar códigos de respaldo (en producción, cifrarlos)
        backup_codes = [secrets.token_hex(4) for _ in range(10)]
        
        return TOTPSetupResponse(
            secret=secret,
            qr_code_url=qr_url,
            backup_codes=backup_codes
        )
    
    async def enable_totp(self, user_id: int, totp_code: str, password: str) -> bool:
        """
        Habilita TOTP tras verificar el código.
        
        Args:
            user_id: ID del usuario
            totp_code: Código TOTP a verificar
            password: Contraseña para confirmar
        
        Returns:
            True si se habilitó correctamente
        """
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado"
            )
        
        # Verificar contraseña
        if not verify_password(password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Contraseña incorrecta"
            )
        
        # Verificar código TOTP
        if not self._verify_totp(user.totp_secret, totp_code):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Código TOTP incorrecto"
            )
        
        user.totp_enabled = True
        await self.db.commit()
        
        await self._create_audit_log(
            user_id=user.id,
            action="2FA habilitado",
            action_type="2FA_ENABLED",
            success=True
        )
        
        return True
    
    def _verify_totp(self, secret: str, code: str) -> bool:
        """
        Verifica un código TOTP.
        
        Args:
            secret: Secreto TOTP del usuario
            code: Código a verificar
        
        Returns:
            True si el código es válido
        """
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)  # Permite 1 ventana de tiempo
    
    async def _create_audit_log(
        self,
        action: str,
        action_type: str,
        user_id: Optional[int] = None,
        ip_address: Optional[str] = None,
        success: bool = True,
        details: Optional[str] = None
    ):
        """
        Crea un registro en el log de auditoría.
        
        Args:
            action: Descripción de la acción
            action_type: Tipo de acción
            user_id: ID del usuario (opcional)
            ip_address: IP del cliente (opcional)
            success: Si la acción fue exitosa
            details: Detalles adicionales
        """
        if settings.ENABLE_AUDIT_LOGS:
            audit_log = AuditLog(
                user_id=user_id,
                action=action,
                action_type=action_type,
                ip_address=ip_address,
                success=success,
                details=details
            )
            self.db.add(audit_log)
            await self.db.commit()
