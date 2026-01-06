# Script de PowerShell para configurar tarea programada de rotación de claves
# Ejecutar con permisos de administrador

$taskName = "ChatSeguro-RotacionClaves"
$scriptPath = "$PSScriptRoot\rotate_keys_auto.py"
$pythonPath = "$PSScriptRoot\venv\Scripts\python.exe"
$workingDir = "$PSScriptRoot"

Write-Host "🔧 Configurando tarea programada para rotación automática de claves..." -ForegroundColor Cyan
Write-Host ""

# Verificar que existen los archivos necesarios
if (-not (Test-Path $scriptPath)) {
    Write-Host "❌ Error: No se encuentra el script rotate_keys_auto.py" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $pythonPath)) {
    Write-Host "❌ Error: No se encuentra Python en el entorno virtual" -ForegroundColor Red
    Write-Host "   Ruta esperada: $pythonPath" -ForegroundColor Yellow
    exit 1
}

# Eliminar tarea existente si existe
$existingTask = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existingTask) {
    Write-Host "⚠️  Eliminando tarea programada existente..." -ForegroundColor Yellow
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
}

# Crear la acción (ejecutar el script)
$action = New-ScheduledTaskAction `
    -Execute $pythonPath `
    -Argument $scriptPath `
    -WorkingDirectory $workingDir

# Crear el trigger (ejecutar diariamente a las 2:00 AM)
$trigger = New-ScheduledTaskTrigger -Daily -At 2:00AM

# Configuración de la tarea
$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -RunOnlyIfNetworkAvailable

# Descripción de la tarea
$description = "Rotación automática de claves RSA del sistema Chat Seguro. Verifica y rota claves vencidas según la política de seguridad (cada 90 días)."

# Registrar la tarea
try {
    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $trigger `
        -Settings $settings `
        -Description $description `
        -User "SYSTEM" `
        -RunLevel Highest
    
    Write-Host "✅ Tarea programada creada exitosamente" -ForegroundColor Green
    Write-Host ""
    Write-Host "📋 Detalles de la tarea:" -ForegroundColor Cyan
    Write-Host "   Nombre: $taskName"
    Write-Host "   Frecuencia: Diaria a las 2:00 AM"
    Write-Host "   Script: $scriptPath"
    Write-Host "   Python: $pythonPath"
    Write-Host ""
    Write-Host "🔍 Para verificar la tarea:" -ForegroundColor Yellow
    Write-Host "   Get-ScheduledTask -TaskName '$taskName'"
    Write-Host ""
    Write-Host "▶️  Para ejecutar manualmente:" -ForegroundColor Yellow
    Write-Host "   Start-ScheduledTask -TaskName '$taskName'"
    Write-Host ""
    Write-Host "📊 Para ver el historial:" -ForegroundColor Yellow
    Write-Host "   Get-ScheduledTaskInfo -TaskName '$taskName'"
    Write-Host ""
    
} catch {
    Write-Host "❌ Error al crear la tarea programada: $_" -ForegroundColor Red
    exit 1
}

# Preguntar si desea ejecutar una prueba
$test = Read-Host "¿Desea ejecutar una verificación de prueba ahora? (s/n)"
if ($test -eq "s" -or $test -eq "S") {
    Write-Host ""
    Write-Host "🧪 Ejecutando verificación de prueba..." -ForegroundColor Cyan
    & $pythonPath $scriptPath --check-only
}
