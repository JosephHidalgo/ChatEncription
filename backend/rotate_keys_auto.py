"""
Script de rotación automática de claves RSA.
Ejecuta la verificación y rotación de claves vencidas según la política de seguridad.

Uso:
    python rotate_keys_auto.py

Política:
    - Rota claves cada KEY_ROTATION_DAYS días (default: 90)
    - Registra todas las rotaciones en el historial
    - Audita cada operación
    - Puede ejecutarse como tarea programada (cron job)
"""
import asyncio
import sys
from pathlib import Path

# Agregar el directorio raíz al path para importar módulos
sys.path.insert(0, str(Path(__file__).parent))

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from app.core.config import settings
from app.services.auth_service import AuthService
from datetime import datetime
import logging

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('key_rotation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


async def run_automatic_key_rotation():
    """
    Ejecuta la rotación automática de claves vencidas.
    """
    logger.info("="*60)
    logger.info("🔄 INICIANDO ROTACIÓN AUTOMÁTICA DE CLAVES")
    logger.info(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info(f"Política: Rotar claves cada {settings.KEY_ROTATION_DAYS} días")
    logger.info("="*60)
    
    # Crear motor de base de datos
    engine = create_async_engine(
        settings.DATABASE_URL,
        echo=False,
        pool_size=5,
        max_overflow=10
    )
    
    # Crear sesión
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    try:
        async with async_session() as session:
            auth_service = AuthService(session)
            
            logger.info("🔍 Verificando usuarios con claves vencidas...")
            
            # Ejecutar rotación de claves vencidas
            rotated_users = await auth_service.check_and_rotate_expired_keys()
            
            if not rotated_users:
                logger.info("✅ No se encontraron claves vencidas.")
            else:
                logger.info(f"✅ Se rotaron las claves de {len(rotated_users)} usuario(s):")
                logger.info("")
                
                for user_data in rotated_users:
                    logger.info(f"  👤 Usuario: {user_data['username']} (ID: {user_data['user_id']})")
                    logger.info(f"     ├─ Rotación anterior: {user_data['old_rotation_date'].strftime('%Y-%m-%d')}")
                    logger.info(f"     ├─ Nueva rotación: {user_data['new_rotation_date'].strftime('%Y-%m-%d')}")
                    logger.info(f"     └─ Razón: {user_data['reason']}")
                    logger.info("")
            
            logger.info("="*60)
            logger.info("✅ ROTACIÓN AUTOMÁTICA COMPLETADA EXITOSAMENTE")
            logger.info("="*60)
            
    except Exception as e:
        logger.error(f"❌ ERROR en rotación automática: {str(e)}")
        logger.exception(e)
        sys.exit(1)
    
    finally:
        await engine.dispose()


async def check_keys_status():
    """
    Verifica el estado de todas las claves sin rotarlas.
    Útil para reportes y monitoreo.
    """
    logger.info("="*60)
    logger.info("📊 VERIFICACIÓN DE ESTADO DE CLAVES")
    logger.info(f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("="*60)
    
    engine = create_async_engine(
        settings.DATABASE_URL,
        echo=False,
        pool_size=5,
        max_overflow=10
    )
    
    async_session = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )
    
    try:
        async with async_session() as session:
            from sqlalchemy import select
            from app.models.models import User
            from datetime import timedelta
            
            # Obtener todos los usuarios activos
            result = await session.execute(
                select(User).where(User.is_active == True)
            )
            users = result.scalars().all()
            
            rotation_threshold = datetime.utcnow() - timedelta(days=settings.KEY_ROTATION_DAYS)
            warning_threshold = datetime.utcnow() - timedelta(days=settings.KEY_ROTATION_DAYS - 7)
            
            expired_count = 0
            warning_count = 0
            valid_count = 0
            
            logger.info(f"Total de usuarios activos: {len(users)}")
            logger.info("")
            
            for user in users:
                days_since_rotation = (datetime.utcnow() - user.key_rotation_date).days
                days_until_expiration = settings.KEY_ROTATION_DAYS - days_since_rotation
                
                if user.key_rotation_date < rotation_threshold:
                    # Clave vencida
                    expired_count += 1
                    logger.warning(f"❌ {user.username} (ID: {user.id})")
                    logger.warning(f"   └─ Vencida hace {abs(days_until_expiration)} días")
                elif user.key_rotation_date < warning_threshold:
                    # Clave próxima a vencer
                    warning_count += 1
                    logger.warning(f"⚠️  {user.username} (ID: {user.id})")
                    logger.warning(f"   └─ Vence en {days_until_expiration} días")
                else:
                    # Clave válida
                    valid_count += 1
                    logger.info(f"✅ {user.username} (ID: {user.id})")
                    logger.info(f"   └─ Válida por {days_until_expiration} días más")
            
            logger.info("")
            logger.info("="*60)
            logger.info(f"📈 RESUMEN:")
            logger.info(f"   ✅ Claves válidas: {valid_count}")
            logger.info(f"   ⚠️  Próximas a vencer: {warning_count}")
            logger.info(f"   ❌ Claves vencidas: {expired_count}")
            logger.info("="*60)
            
    except Exception as e:
        logger.error(f"❌ ERROR en verificación: {str(e)}")
        logger.exception(e)
        sys.exit(1)
    
    finally:
        await engine.dispose()


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Rotación automática de claves RSA")
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Solo verifica el estado sin rotar claves"
    )
    
    args = parser.parse_args()
    
    if args.check_only:
        asyncio.run(check_keys_status())
    else:
        asyncio.run(run_automatic_key_rotation())
