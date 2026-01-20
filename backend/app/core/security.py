"""
Módulo de seguridad para manejo de contraseñas y tokens JWT.
Implementa las mejores prácticas de seguridad para autenticación.
"""
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from jose import JWTError, jwt
from passlib.context import CryptContext
from app.core.config import settings
import secrets


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica que una contraseña en texto plano coincida con su hash.
    
    Args:
        plain_password: Contraseña en texto plano
        hashed_password: Hash de la contraseña almacenada
    
    Returns:
        True si coinciden, False en caso contrario
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Genera un hash seguro de la contraseña usando bcrypt.
    
    Args:
        password: Contraseña en texto plano
    
    Returns:
        Hash de la contraseña
    """
    return pwd_context.hash(password)


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Valida la fortaleza de una contraseña según políticas de seguridad.
    
    Args:
        password: Contraseña a validar
    
    Returns:
        Tupla (es_válida, mensaje_error)
    """
    if len(password) < settings.PASSWORD_MIN_LENGTH:
        return False, f"La contraseña debe tener al menos {settings.PASSWORD_MIN_LENGTH} caracteres"
    
    if not any(c.isupper() for c in password):
        return False, "La contraseña debe contener al menos una mayúscula"
    
    if not any(c.islower() for c in password):
        return False, "La contraseña debe contener al menos una minúscula"
    
    if not any(c.isdigit() for c in password):
        return False, "La contraseña debe contener al menos un número"
    
    if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
        return False, "La contraseña debe contener al menos un carácter especial"
    
    return True, "Contraseña válida"


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """
    Crea un token JWT de acceso.
    
    Args:
        data: Datos a codificar en el token (por ejemplo, {"sub": user_id})
        expires_delta: Tiempo de expiración personalizado
    
    Returns:
        Token JWT codificado
    """
    to_encode = data.copy()
    
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "access"
    })
    
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def create_refresh_token(data: Dict[str, Any]) -> str:
    """
    Crea un token JWT de refresco con mayor tiempo de expiración.
    
    Args:
        data: Datos a codificar en el token
    
    Returns:
        Token JWT de refresco
    """
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    to_encode.update({
        "exp": expire,
        "iat": datetime.utcnow(),
        "type": "refresh"
    })
    
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Decodifica y valida un token JWT.
    
    Args:
        token: Token JWT a decodificar
    
    Returns:
        Payload del token si es válido, None en caso contrario
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except JWTError:
        return None


def generate_random_key(length: int = 32) -> str:
    """
    Genera una clave aleatoria criptográficamente segura.
    
    Args:
        length: Longitud de la clave en bytes
    
    Returns:
        Clave en formato hexadecimal
    """
    return secrets.token_hex(length)


def generate_totp_secret() -> str:
    """
    Genera un secreto para TOTP (Time-based One-Time Password).
    
    Returns:
        Secreto TOTP en formato base32
    """
    return secrets.token_urlsafe(32)
