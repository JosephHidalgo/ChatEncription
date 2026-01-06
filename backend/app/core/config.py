"""
Configuración centralizada de la aplicación.
Carga variables de entorno y define configuraciones de seguridad.
"""
from pydantic_settings import BaseSettings
from typing import List
from functools import lru_cache


class Settings(BaseSettings):
    """
    Configuración de la aplicación con validación de Pydantic.
    Todas las variables se cargan desde el archivo .env
    """
    
    # Información de la Aplicación
    APP_NAME: str = "Sistema de Chat Seguro"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True
    
    # Servidor
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Seguridad JWT
    SECRET_KEY: str
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    
    # Base de Datos PostgreSQL
    DATABASE_URL: str
    DATABASE_POOL_SIZE: int = 10
    DATABASE_MAX_OVERFLOW: int = 20
    
    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"
    REDIS_SESSION_DB: int = 1
    
    # Configuración de Cifrado
    RSA_KEY_SIZE: int = 2048
    AES_KEY_SIZE: int = 256
    KEY_ROTATION_DAYS: int = 90
    SESSION_KEY_ROTATION_HOURS: int = 24
    
    # Rate Limiting
    RATE_LIMIT_LOGIN: str = "5/15minute"
    RATE_LIMIT_MESSAGES: str = "100/1minute"
    RATE_LIMIT_WEBSOCKET: str = "3/1minute"
    
    # Contraseñas
    PASSWORD_MIN_LENGTH: int = 12
    BCRYPT_ROUNDS: int = 12
    
    # CORS - Configuración para red local
    # En desarrollo: permite todos los orígenes
    # En producción: especificar orígenes exactos
    CORS_ORIGINS: List[str] = ["*"]  # Permite cualquier origen
    ALLOW_ALL_ORIGINS: bool = True  # Flag para permitir todos los orígenes
    
    # Auditoría
    ENABLE_AUDIT_LOGS: bool = True
    LOG_LEVEL: str = "INFO"
    
    class Config:
        env_file = ".env"
        case_sensitive = True


@lru_cache()
def get_settings() -> Settings:
    """
    Obtiene la instancia de configuración (singleton).
    Usa caché para evitar recargar en cada llamada.
    """
    return Settings()


# Instancia global de configuración
settings = get_settings()
