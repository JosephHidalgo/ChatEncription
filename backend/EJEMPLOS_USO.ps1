# Ejemplos de Uso - Rotación de Claves
# Copia y pega estos comandos para probar el sistema

# =============================================================================
# PASO 1: INICIAR EL SERVIDOR
# =============================================================================

# Activar entorno virtual (si no está activado)
cd "D:\UNAP\VIII SEMESTRE\SEGURIDAD EN SISTEMAS INFORMATICOS\Proyecto Final\backend"
.\venv\Scripts\Activate.ps1

# Iniciar servidor FastAPI
python main.py

# El servidor estará disponible en: http://localhost:8000
# Documentación interactiva: http://localhost:8000/docs


# =============================================================================
# PASO 2: VERIFICAR ESTADO DE CLAVES (SIN ROTAR)
# =============================================================================

# En otra terminal PowerShell
cd "D:\UNAP\VIII SEMESTRE\SEGURIDAD EN SISTEMAS INFORMATICOS\Proyecto Final\backend"
.\venv\Scripts\Activate.ps1

# Verificar estado de todas las claves
python rotate_keys_auto.py --check-only


# =============================================================================
# PASO 3: EJECUTAR PRUEBA DE ROTACIÓN
# =============================================================================

# Ejecutar prueba completa del sistema
python test_rotation.py


# =============================================================================
# PASO 4: ROTAR CLAVES AUTOMÁTICAMENTE
# =============================================================================

# Ejecutar rotación de claves vencidas
python rotate_keys_auto.py


# =============================================================================
# PASO 5: VER LOGS DE ROTACIÓN
# =============================================================================

# Ver últimas 20 líneas del log
Get-Content key_rotation.log -Tail 20

# Ver todo el log
Get-Content key_rotation.log

# Seguir el log en tiempo real (para monitoreo)
Get-Content key_rotation.log -Wait


# =============================================================================
# PASO 6: CONFIGURAR TAREA PROGRAMADA (OPCIONAL)
# =============================================================================

# IMPORTANTE: Ejecutar PowerShell como ADMINISTRADOR

# Configurar tarea programada para rotación automática
cd "D:\UNAP\VIII SEMESTRE\SEGURIDAD EN SISTEMAS INFORMATICOS\Proyecto Final\backend"
.\setup_rotation_task.ps1

# Verificar que la tarea se creó
Get-ScheduledTask -TaskName "ChatSeguro-RotacionClaves"

# Ejecutar la tarea manualmente (para probar)
Start-ScheduledTask -TaskName "ChatSeguro-RotacionClaves"

# Ver información de la tarea
Get-ScheduledTaskInfo -TaskName "ChatSeguro-RotacionClaves"

# Ver historial de ejecuciones
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-TaskScheduler/Operational'; ID=201} -MaxEvents 10 | 
    Where-Object {$_.Message -like "*ChatSeguro-RotacionClaves*"}


# =============================================================================
# PASO 7: PROBAR ENDPOINTS DE API
# =============================================================================

# Primero necesitas obtener un token de acceso
# 1. Ir a http://localhost:8000/docs
# 2. Ejecutar POST /auth/login con tus credenciales
# 3. Copiar el access_token

# O usar curl/Invoke-WebRequest:

# --- LOGIN ---
$loginData = @{
    username = "tu_usuario"
    password = "tu_contraseña"
} | ConvertTo-Json

$response = Invoke-WebRequest -Uri "http://localhost:8000/auth/login" `
    -Method POST `
    -Body $loginData `
    -ContentType "application/json"

$token = ($response.Content | ConvertFrom-Json).access_token
Write-Host "Token obtenido: $token"


# --- VERIFICAR ESTADO DE CLAVES ---
$headers = @{
    "Authorization" = "Bearer $token"
}

Invoke-WebRequest -Uri "http://localhost:8000/auth/keys/check-expiration" `
    -Method GET `
    -Headers $headers | 
    Select-Object -ExpandProperty Content | 
    ConvertFrom-Json | 
    ConvertTo-Json -Depth 10


# --- ROTAR CLAVES MANUALMENTE ---
$rotationData = @{
    password = "tu_contraseña"
    reason = "Prueba de rotación manual desde PowerShell"
} | ConvertTo-Json

Invoke-WebRequest -Uri "http://localhost:8000/auth/keys/rotate" `
    -Method POST `
    -Headers $headers `
    -Body $rotationData `
    -ContentType "application/json" | 
    Select-Object -ExpandProperty Content | 
    ConvertFrom-Json | 
    ConvertTo-Json -Depth 10


# --- VER HISTORIAL DE ROTACIONES ---
Invoke-WebRequest -Uri "http://localhost:8000/auth/keys/rotation-history?limit=5" `
    -Method GET `
    -Headers $headers | 
    Select-Object -ExpandProperty Content | 
    ConvertFrom-Json | 
    ConvertTo-Json -Depth 10


# =============================================================================
# PASO 8: VERIFICAR BASE DE DATOS
# =============================================================================

# Ver registros de rotación en la base de datos
cd "D:\UNAP\VIII SEMESTRE\SEGURIDAD EN SISTEMAS INFORMATICOS\Proyecto Final\backend"
python -c "
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import select, text
from app.core.config import settings
from app.models.models import KeyRotationHistory, AuditLog

async def check_db():
    engine = create_async_engine(settings.DATABASE_URL)
    async_session = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    
    async with async_session() as session:
        # Ver últimas rotaciones
        print('\\n📋 HISTORIAL DE ROTACIONES:')
        print('='*70)
        result = await session.execute(
            select(KeyRotationHistory)
            .order_by(KeyRotationHistory.rotated_at.desc())
            .limit(5)
        )
        for r in result.scalars():
            print(f'Usuario {r.user_id}: {r.rotated_at} - {r.rotation_reason}')
        
        # Ver logs de auditoría relacionados
        print('\\n📊 LOGS DE AUDITORÍA (KEY_ROTATION):')
        print('='*70)
        result = await session.execute(
            select(AuditLog)
            .where(AuditLog.action_type == 'KEY_ROTATION')
            .order_by(AuditLog.timestamp.desc())
            .limit(5)
        )
        for log in result.scalars():
            print(f'{log.timestamp}: {log.action}')
    
    await engine.dispose()

asyncio.run(check_db())
"


# =============================================================================
# PASO 9: LIMPIAR (OPCIONAL)
# =============================================================================

# Desactivar tarea programada (si se configuró)
Disable-ScheduledTask -TaskName "ChatSeguro-RotacionClaves"

# Eliminar tarea programada (si se configuró)
Unregister-ScheduledTask -TaskName "ChatSeguro-RotacionClaves" -Confirm:$false

# Limpiar logs
Remove-Item key_rotation.log -ErrorAction SilentlyContinue


# =============================================================================
# DEMOSTRACIÓN COMPLETA PARA EL DOCENTE
# =============================================================================

Write-Host "================================" -ForegroundColor Cyan
Write-Host "DEMOSTRACIÓN DE ROTACIÓN DE CLAVES" -ForegroundColor Cyan
Write-Host "================================" -ForegroundColor Cyan

# 1. Verificar estado
Write-Host "`n1️⃣ Verificando estado de claves..." -ForegroundColor Yellow
python rotate_keys_auto.py --check-only

# 2. Ejecutar prueba
Write-Host "`n2️⃣ Ejecutando prueba de rotación..." -ForegroundColor Yellow
python test_rotation.py

# 3. Ver logs
Write-Host "`n3️⃣ Mostrando logs de rotación..." -ForegroundColor Yellow
Get-Content key_rotation.log -Tail 10

Write-Host "`n✅ Demostración completada!" -ForegroundColor Green
Write-Host "📖 Ver documentación completa en: KEY_ROTATION_GUIDE.md" -ForegroundColor Cyan
