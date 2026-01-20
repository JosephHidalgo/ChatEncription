"""
Servicio de autenticación y gestión de usuarios.
Maneja registro, login, 2FA, sesiones y auditoría.
"""
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from fastapi import HTTPException, status
from datetime import datetime, timedelta
from typing import Optional, Tuple, Dict, List
import secrets
import pyotp
from app.models.models import User, Session, AuditLog, KeyRotationHistory
from app.schemas.schemas import UserCreate, UserLogin, Token, TOTPSetupResponse, KeyRotationResponse
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
        
        
        if user_data.public_key:
            # El cliente maneja sus claves
            public_key_pem_str = user_data.public_key
            # Guardar clave privada cifrada si el cliente la envió
            encrypted_private_key = None
            if user_data.encrypted_private_key:
                # Convertir de string a bytes para guardar en LargeBinary
                encrypted_private_key = user_data.encrypted_private_key.encode('utf-8')
        else:
            # Generar par de claves RSA en el servidor (legacy)
            private_key_pem, public_key_pem = crypto_manager.generate_rsa_key_pair()
            public_key_pem_str = public_key_pem.decode('utf-8')
            encrypted_private_key = private_key_pem 
        
        # Crear usuario
        new_user = User(
            username=user_data.username,
            email=user_data.email,
            password_hash=password_hash,
            public_key_rsa=public_key_pem_str,
            encrypted_private_key_rsa=encrypted_private_key,
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
        
        secret = pyotp.random_base32()
        user.totp_secret = secret
        await self.db.commit()
        
        totp = pyotp.TOTP(secret)
        qr_url = totp.provisioning_uri(
            name=user.email,
            issuer_name=settings.APP_NAME
        )
        
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
    
    # ===================== ROTACIÓN DE CLAVES =====================
    
    async def rotate_user_keys(
        self,
        user_id: int,
        reason: str = "Rotación manual",
        ip_address: Optional[str] = None
    ) -> KeyRotationResponse:
        """
        Rota las claves RSA de un usuario.
        
        Políticas de Seguridad:
        - Genera nuevo par de claves RSA
        - Registra la rotación en el historial
        - Audita la operación
        - Actualiza la fecha de rotación
        
        Args:
            user_id: ID del usuario
            reason: Razón de la rotación
            ip_address: IP del cliente (opcional)
        
        Returns:
            Información de la rotación con las nuevas claves
        """
        # Buscar usuario
        result = await self.db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado"
            )
        
        # Guardar claves antiguas para el historial
        old_public_key = user.public_key_rsa
        
        # Generar nuevo par de claves RSA
        private_key_pem, public_key_pem = crypto_manager.generate_rsa_key_pair()
        
        # Actualizar claves del usuario
        user.public_key_rsa = public_key_pem.decode('utf-8')
        user.key_rotation_date = datetime.utcnow()
        
        # Registrar en historial de rotación
        rotation_history = KeyRotationHistory(
            user_id=user.id,
            old_public_key=old_public_key,
            new_public_key=user.public_key_rsa,
            rotation_reason=reason,
            rotated_at=datetime.utcnow()
        )
        self.db.add(rotation_history)
        
        # Auditar la rotación
        await self._create_audit_log(
            user_id=user.id,
            action=f"Rotación de claves RSA: {reason}",
            action_type="KEY_ROTATION",
            ip_address=ip_address,
            success=True,
            details=f"Razón: {reason}"
        )
        
        await self.db.commit()
        await self.db.refresh(user)
        
        return KeyRotationResponse(
            user_id=user.id,
            public_key_rsa=user.public_key_rsa,
            private_key_rsa=private_key_pem.decode('utf-8'),
            rotated_at=user.key_rotation_date,
            reason=reason
        )
    
    async def check_and_rotate_expired_keys(self) -> List[Dict]:
        """
        Verifica y rota claves vencidas según la política de rotación.
        
        Política: Rotar claves cada KEY_ROTATION_DAYS días (por defecto 90).
        
        Returns:
            Lista de usuarios cuyas claves fueron rotadas
        """
        rotation_threshold = datetime.utcnow() - timedelta(days=settings.KEY_ROTATION_DAYS)
        
        # Buscar usuarios con claves vencidas
        result = await self.db.execute(
            select(User).where(
                User.key_rotation_date < rotation_threshold,
                User.is_active == True
            )
        )
        users_to_rotate = result.scalars().all()
        
        rotated_users = []
        
        for user in users_to_rotate:
            try:
                # Rotar claves automáticamente
                rotation_result = await self.rotate_user_keys(
                    user_id=user.id,
                    reason=f"Rotación automática (claves vencidas desde {user.key_rotation_date.date()})",
                    ip_address="Sistema"
                )
                
                rotated_users.append({
                    "user_id": user.id,
                    "username": user.username,
                    "old_rotation_date": user.key_rotation_date,
                    "new_rotation_date": rotation_result.rotated_at,
                    "reason": rotation_result.reason
                })
                
            except Exception as e:
                # Registrar error pero continuar con otros usuarios
                await self._create_audit_log(
                    user_id=user.id,
                    action=f"Error en rotación automática: {str(e)}",
                    action_type="KEY_ROTATION_ERROR",
                    success=False,
                    details=str(e)
                )
        
        return rotated_users
    
    async def get_rotation_history(
        self,
        user_id: int,
        limit: int = 10
    ) -> List[KeyRotationHistory]:
        """
        Obtiene el historial de rotaciones de claves de un usuario.
        
        Args:
            user_id: ID del usuario
            limit: Número máximo de registros a devolver
        
        Returns:
            Lista de rotaciones ordenadas por fecha (más reciente primero)
        """
        result = await self.db.execute(
            select(KeyRotationHistory)
            .where(KeyRotationHistory.user_id == user_id)
            .order_by(KeyRotationHistory.rotated_at.desc())
            .limit(limit)
        )
        return result.scalars().all()

