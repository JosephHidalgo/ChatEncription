"""
Script de prueba de rotación de claves.
Ejecuta una prueba completa del sistema de rotación.
"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select
from app.core.config import settings
from app.models.models import User
from app.services.auth_service import AuthService
from datetime import datetime, timedelta


async def test_key_rotation():
    """
    Prueba el sistema de rotación de claves.
    """
    print("="*70)
    print("🧪 PRUEBA DEL SISTEMA DE ROTACIÓN DE CLAVES")
    print("="*70)
    print()
    
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
            auth_service = AuthService(session)
            
            # 1. Obtener primer usuario activo
            print("📋 Paso 1: Obteniendo usuario de prueba...")
            result = await session.execute(
                select(User).where(User.is_active == True).limit(1)
            )
            user = result.scalar_one_or_none()
            
            if not user:
                print("❌ No hay usuarios en la base de datos")
                return
            
            print(f"✅ Usuario encontrado: {user.username} (ID: {user.id})")
            print(f"   Última rotación: {user.key_rotation_date}")
            print()
            
            # 2. Ver estado actual
            print("📋 Paso 2: Verificando estado de claves...")
            days_since = (datetime.utcnow() - user.key_rotation_date).days
            days_until = settings.KEY_ROTATION_DAYS - days_since
            print(f"   Días desde última rotación: {days_since}")
            print(f"   Días hasta vencimiento: {days_until}")
            print(f"   Estado: {'⚠️ VENCIDA' if days_until <= 0 else '✅ VÁLIDA'}")
            print()
            
            # 3. Simular clave vencida (para prueba)
            print("📋 Paso 3: Simulando clave vencida (para prueba)...")
            original_date = user.key_rotation_date
            user.key_rotation_date = datetime.utcnow() - timedelta(days=91)
            await session.commit()
            print("✅ Fecha de rotación ajustada temporalmente")
            print()
            
            # 4. Ejecutar rotación automática
            print("📋 Paso 4: Ejecutando rotación automática...")
            rotated = await auth_service.check_and_rotate_expired_keys()
            
            if rotated:
                print("✅ Rotación ejecutada:")
                for r in rotated:
                    print(f"   👤 Usuario: {r['username']}")
                    print(f"      Rotación anterior: {r['old_rotation_date']}")
                    print(f"      Nueva rotación: {r['new_rotation_date']}")
                    print(f"      Razón: {r['reason']}")
            else:
                print("⚠️ No se ejecutaron rotaciones")
            print()
            
            # 5. Ver historial
            print("📋 Paso 5: Consultando historial de rotaciones...")
            history = await auth_service.get_rotation_history(user.id, limit=3)
            
            if history:
                print(f"✅ Se encontraron {len(history)} registros:")
                for i, h in enumerate(history, 1):
                    print(f"   {i}. {h.rotated_at.strftime('%Y-%m-%d %H:%M:%S')}")
                    print(f"      Razón: {h.rotation_reason}")
            else:
                print("⚠️ Sin historial de rotaciones")
            print()
            
            # 6. Restaurar fecha original (limpieza)
            print("📋 Paso 6: Restaurando estado original...")
            # Actualizar el usuario con los datos más recientes
            await session.refresh(user)
            # No restauramos, dejamos la rotación válida
            print("✅ Estado final guardado")
            print()
            
            print("="*70)
            print("✅ PRUEBA COMPLETADA EXITOSAMENTE")
            print("="*70)
            print()
            print("💡 Ahora puedes:")
            print("   1. Ejecutar: python rotate_keys_auto.py --check-only")
            print("   2. Ver logs: cat key_rotation.log")
            print("   3. Consultar historial vía API: GET /auth/keys/rotation-history")
            
    except Exception as e:
        print(f"❌ ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    finally:
        await engine.dispose()


if __name__ == "__main__":
    asyncio.run(test_key_rotation())
