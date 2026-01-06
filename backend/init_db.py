"""
Script para inicializar la base de datos.
Crea todas las tablas necesarias para el sistema de chat seguro.
"""
import asyncio
from app.core.database import engine, Base
from app.models.models import User, Message, Session, AuditLog, KeyRotationHistory
from loguru import logger


async def init_database():
    """Inicializa todas las tablas de la base de datos"""
    logger.info("Iniciando creación de tablas...")
    
    async with engine.begin() as conn:
        # Eliminar todas las tablas existentes (usar con cuidado)
        # await conn.run_sync(Base.metadata.drop_all)
        
        # Crear todas las tablas
        await conn.run_sync(Base.metadata.create_all)
    
    logger.info("✅ Tablas creadas exitosamente:")
    logger.info("  - users (Usuarios)")
    logger.info("  - messages (Mensajes cifrados)")
    logger.info("  - sessions (Sesiones JWT)")
    logger.info("  - audit_logs (Logs de auditoría)")
    logger.info("  - key_rotation_history (Historial de rotación de claves)")
    
    await engine.dispose()


if __name__ == "__main__":
    asyncio.run(init_database())
