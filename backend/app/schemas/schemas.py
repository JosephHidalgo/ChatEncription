"""
Schemas de Pydantic para validación de datos.
Define los modelos de entrada y salida de la API.
"""
from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional
from datetime import datetime
from app.core.config import settings


# ===================== USUARIOS =====================

class UserBase(BaseModel):
    """Schema base de usuario"""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr


class UserCreate(UserBase):
    """Schema para creación de usuario"""
    password: str = Field(..., min_length=settings.PASSWORD_MIN_LENGTH)
    public_key: Optional[str] = None 
    encrypted_private_key: Optional[str] = None  
    
    @validator('password')
    def validate_password(cls, v):
        """Valida la fortaleza de la contraseña"""
        from app.core.security import validate_password_strength
        is_valid, message = validate_password_strength(v)
        if not is_valid:
            raise ValueError(message)
        return v


class UserLogin(BaseModel):
    """Schema para login"""
    username: str
    password: str
    totp_code: Optional[str] = None


class UserResponse(UserBase):
    """Schema de respuesta de usuario"""
    id: int
    is_active: bool
    is_verified: bool
    totp_enabled: bool
    public_key_rsa: Optional[str] = None
    created_at: datetime
    last_login: Optional[datetime]
    
    class Config:
        from_attributes = True


class UserPublicKey(BaseModel):
    """Schema para compartir clave pública"""
    user_id: int
    username: str
    public_key_rsa: str


# ===================== AUTENTICACIÓN =====================

class Token(BaseModel):
    """Schema para tokens de acceso"""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class TokenData(BaseModel):
    """Datos contenidos en el token"""
    user_id: Optional[int] = None
    username: Optional[str] = None


class RefreshTokenRequest(BaseModel):
    """Schema para refrescar token"""
    refresh_token: str


# ===================== MENSAJES =====================

class MessageCreate(BaseModel):
    """Schema para crear mensaje (antes de cifrar)"""
    recipient_id: int
    content: str = Field(..., max_length=10000)


class MessageEncrypted(BaseModel):
    """Schema para mensaje cifrado"""
    recipient_id: int
    encrypted_content: str
    encrypted_aes_key: str
    iv: str
    signature: str
    nonce: str


class MessageResponse(BaseModel):
    """Schema de respuesta de mensaje"""
    id: int
    sender_id: int
    recipient_id: int
    encrypted_content: str
    encrypted_aes_key: str
    iv: str
    signature: str
    timestamp: datetime
    is_read: bool
    
    class Config:
        from_attributes = True


class MessageDecrypted(BaseModel):
    """Schema para mensaje descifrado (solo para cliente)"""
    id: int
    sender_id: int
    sender_username: str
    content: str
    timestamp: datetime
    signature_valid: bool


# ===================== 2FA / TOTP =====================

class TOTPSetupResponse(BaseModel):
    """Schema para configuración de TOTP"""
    secret: str
    qr_code_url: str
    backup_codes: list[str]


class TOTPVerify(BaseModel):
    """Schema para verificar código TOTP"""
    totp_code: str


class TOTPEnable(BaseModel):
    """Schema para habilitar TOTP"""
    totp_code: str
    password: str


# ===================== SESIONES =====================

class SessionInfo(BaseModel):
    """Información de sesión activa"""
    id: int
    ip_address: Optional[str]
    user_agent: Optional[str]
    created_at: datetime
    last_activity: datetime
    expires_at: datetime
    
    class Config:
        from_attributes = True


# ===================== AUDITORÍA =====================

class AuditLogCreate(BaseModel):
    """Schema para crear log de auditoría"""
    action: str
    action_type: str
    details: Optional[str] = None
    success: bool = True


class AuditLogResponse(BaseModel):
    """Schema de respuesta de log de auditoría"""
    id: int
    user_id: Optional[int]
    action: str
    action_type: str
    details: Optional[str]
    success: bool
    ip_address: Optional[str]
    timestamp: datetime
    
    class Config:
        from_attributes = True


# ===================== WEBSOCKET =====================

class WebSocketMessage(BaseModel):
    """Schema para mensajes WebSocket"""
    type: str  # 'message', 'notification', 'typing', 'read_receipt'
    data: dict


class TypingNotification(BaseModel):
    """Notificación de escritura"""
    recipient_id: int
    is_typing: bool


class ReadReceipt(BaseModel):
    """Confirmación de lectura"""
    message_id: int


# ===================== ROTACIÓN DE CLAVES =====================

class KeyRotationRequest(BaseModel):
    """Schema para solicitar rotación de claves"""
    password: str
    reason: Optional[str] = "Rotación manual"


class KeyRotationResponse(BaseModel):
    """Schema de respuesta de rotación"""
    user_id: int
    public_key_rsa: str
    private_key_rsa: str
    rotated_at: datetime
    reason: str


# ===================== GRUPOS =====================

class GroupCreate(BaseModel):
    """Schema para creación de grupo"""
    name: str = Field(..., min_length=3, max_length=100)
    description: Optional[str] = Field(None, max_length=500)
    member_ids: list[int] = Field(default_factory=list)  # IDs de miembros iniciales
    encrypted_keys: dict[str, str]  # {user_id: encrypted_group_key}
    group_key_hash: str  # SHA-256 hash de la clave AES del grupo


class GroupUpdate(BaseModel):
    """Schema para actualización de grupo"""
    name: Optional[str] = Field(None, min_length=3, max_length=100)
    description: Optional[str] = None


class GroupMemberResponse(BaseModel):
    """Schema de respuesta de miembro de grupo"""
    id: int
    user_id: int
    username: str
    is_admin: bool
    can_send_messages: bool
    can_add_members: bool
    joined_at: datetime
    
    class Config:
        from_attributes = True


class GroupResponse(BaseModel):
    """Schema de respuesta de grupo"""
    id: int
    name: str
    description: Optional[str]
    admin_id: int
    created_at: datetime
    is_active: bool
    member_count: Optional[int] = None
    
    class Config:
        from_attributes = True


class GroupDetailResponse(GroupResponse):
    """Schema de respuesta detallada de grupo (incluye miembros)"""
    members: list[GroupMemberResponse]


class GroupMessageCreate(BaseModel):
    """Schema para crear mensaje de grupo"""
    group_id: int
    encrypted_content: str
    iv: str
    signature: str


class GroupMessageResponse(BaseModel):
    """Schema de respuesta de mensaje de grupo"""
    id: int
    group_id: int
    sender_id: int
    sender_username: str
    encrypted_content: str
    iv: str
    signature: str
    timestamp: datetime
    nonce: str
    
    class Config:
        from_attributes = True


class AddMemberRequest(BaseModel):
    """Schema para agregar miembro a grupo"""
    user_id: int
    encrypted_group_key: str  # Clave AES del grupo encriptada con RSA del nuevo miembro


class JoinGroupWithCodeRequest(BaseModel):
    """Schema para unirse a grupo con código"""
    code: str
    encrypted_group_key: str  # Cliente encripta la clave con su propia RSA


class InviteCodeCreate(BaseModel):
    """Schema para crear código de invitación"""
    max_uses: Optional[int] = None  # None = ilimitado
    expires_in_hours: Optional[int] = None  # None = no expira


class InviteCodeResponse(BaseModel):
    """Schema de respuesta de código de invitación"""
    id: int
    code: str
    group_id: int
    group_name: str
    max_uses: Optional[int]
    current_uses: int
    expires_at: Optional[datetime]
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


class GroupKeyDistribution(BaseModel):
    """Schema para distribuir clave de grupo a miembros"""
    group_id: int
    encrypted_keys: dict[int, str]  # {user_id: encrypted_group_key}

