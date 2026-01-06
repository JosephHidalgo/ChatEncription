# Guía de Rotación de Claves - Sistema Chat Seguro

## 📋 Descripción

Este documento describe cómo funciona la rotación de claves RSA en el sistema Chat Seguro y cómo utilizarla.

---

## 🔐 Política de Rotación de Claves

### Objetivo
Minimizar el riesgo de compromiso de claves mediante rotación periódica automática y manual.

### Políticas Implementadas

1. **Rotación Automática**
   - Frecuencia: Cada 90 días (configurable en `KEY_ROTATION_DAYS`)
   - Ejecución: Diaria a las 2:00 AM mediante tarea programada
   - Alcance: Todos los usuarios activos con claves vencidas

2. **Rotación Manual**
   - Disponible en cualquier momento a través del endpoint `/auth/keys/rotate`
   - Requiere confirmación con contraseña del usuario
   - Útil para compromisos de seguridad o cambios preventivos

3. **Auditoría**
   - Todas las rotaciones se registran en `key_rotation_history`
   - Log de auditoría con timestamp, razón y resultado
   - Archivo de log: `key_rotation.log`

---

## 🚀 Uso

### 1. Rotación Manual (API)

**Endpoint:** `POST /auth/keys/rotate`

**Request:**
```json
{
  "password": "tu_contraseña_actual",
  "reason": "Rotación manual por actualización de seguridad"
}
```

**Response:**
```json
{
  "user_id": 1,
  "public_key_rsa": "-----BEGIN PUBLIC KEY-----\n...",
  "private_key_rsa": "-----BEGIN PRIVATE KEY-----\n...",
  "rotated_at": "2026-01-06T15:30:00",
  "reason": "Rotación manual por actualización de seguridad"
}
```

**Importante:** Guarda la nueva `private_key_rsa` de forma segura en el cliente.

---

### 2. Verificar Estado de Claves

**Endpoint:** `GET /auth/keys/check-expiration`

**Response:**
```json
{
  "user_id": 1,
  "last_rotation": "2025-10-08T10:00:00",
  "days_since_rotation": 90,
  "days_until_expiration": 0,
  "rotation_policy_days": 90,
  "is_expired": true,
  "is_expiring_soon": false,
  "message": "¡Claves vencidas! Rota tus claves inmediatamente."
}
```

---

### 3. Ver Historial de Rotaciones

**Endpoint:** `GET /auth/keys/rotation-history?limit=10`

**Response:**
```json
[
  {
    "id": 5,
    "rotated_at": "2026-01-06T02:00:00",
    "rotation_reason": "Rotación automática (claves vencidas desde 2025-10-08)",
    "old_public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgk...",
    "new_public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgk..."
  }
]
```

---

## 🔧 Rotación Automática con Script

### Ejecutar Verificación (sin rotar)

```powershell
# Desde el directorio backend
python rotate_keys_auto.py --check-only
```

**Salida:**
```
📊 VERIFICACIÓN DE ESTADO DE CLAVES
Fecha: 2026-01-06 15:30:00
============================================================
Total de usuarios activos: 3

✅ usuario1 (ID: 1)
   └─ Válida por 45 días más
⚠️  usuario2 (ID: 2)
   └─ Vence en 5 días
❌ usuario3 (ID: 3)
   └─ Vencida hace 10 días

============================================================
📈 RESUMEN:
   ✅ Claves válidas: 1
   ⚠️  Próximas a vencer: 1
   ❌ Claves vencidas: 1
============================================================
```

### Ejecutar Rotación Automática

```powershell
python rotate_keys_auto.py
```

**Salida:**
```
🔄 INICIANDO ROTACIÓN AUTOMÁTICA DE CLAVES
Fecha: 2026-01-06 15:30:00
Política: Rotar claves cada 90 días
============================================================
🔍 Verificando usuarios con claves vencidas...
✅ Se rotaron las claves de 1 usuario(s):

  👤 Usuario: usuario3 (ID: 3)
     ├─ Rotación anterior: 2025-09-28
     ├─ Nueva rotación: 2026-01-06
     └─ Razón: Rotación automática (claves vencidas desde 2025-09-28)

============================================================
✅ ROTACIÓN AUTOMÁTICA COMPLETADA EXITOSAMENTE
============================================================
```

---

## ⏰ Configurar Tarea Programada (Windows)

### Instalación

```powershell
# Ejecutar con permisos de administrador
cd backend
.\setup_rotation_task.ps1
```

### Verificar Tarea

```powershell
Get-ScheduledTask -TaskName "ChatSeguro-RotacionClaves"
```

### Ejecutar Manualmente

```powershell
Start-ScheduledTask -TaskName "ChatSeguro-RotacionClaves"
```

### Ver Historial de Ejecuciones

```powershell
Get-ScheduledTaskInfo -TaskName "ChatSeguro-RotacionClaves"
```

### Eliminar Tarea

```powershell
Unregister-ScheduledTask -TaskName "ChatSeguro-RotacionClaves" -Confirm:$false
```

---

## 📝 Logs de Rotación

Los logs se guardan en: `backend/key_rotation.log`

```log
2026-01-06 02:00:00 - INFO - 🔄 INICIANDO ROTACIÓN AUTOMÁTICA DE CLAVES
2026-01-06 02:00:00 - INFO - Política: Rotar claves cada 90 días
2026-01-06 02:00:01 - INFO - 🔍 Verificando usuarios con claves vencidas...
2026-01-06 02:00:02 - INFO - ✅ Se rotaron las claves de 2 usuario(s):
2026-01-06 02:00:02 - INFO -   👤 Usuario: usuario3 (ID: 3)
2026-01-06 02:00:02 - INFO -      ├─ Rotación anterior: 2025-09-28
2026-01-06 02:00:02 - INFO -      ├─ Nueva rotación: 2026-01-06
2026-01-06 02:00:02 - INFO -      └─ Razón: Rotación automática
```

---

## 🔒 Consideraciones de Seguridad

### ⚠️ Importantes

1. **Claves Privadas**
   - La rotación manual devuelve la clave privada al cliente
   - El cliente DEBE almacenarla de forma segura (localStorage cifrado, IndexedDB, etc.)
   - NUNCA almacenar en texto plano

2. **Mensajes Antiguos**
   - Los mensajes cifrados con claves antiguas pueden volverse ilegibles
   - Implementar re-cifrado de mensajes en producción
   - O mantener un período de gracia con claves antiguas

3. **Sincronización**
   - Si un usuario tiene múltiples dispositivos, debe sincronizar la nueva clave privada
   - Implementar mecanismo de backup/restauración

4. **Notificaciones**
   - El sistema debe notificar a los usuarios cuando sus claves están por vencer
   - Implementar alertas en el frontend

### ✅ Mejores Prácticas

1. Configurar alertas para claves próximas a vencer (7 días antes)
2. Realizar respaldos regulares de la base de datos
3. Monitorear el archivo `key_rotation.log` regularmente
4. Verificar el estado de la tarea programada semanalmente
5. Documentar todas las rotaciones manuales con razón clara

---

## 🧪 Pruebas

### 1. Probar Rotación Manual

```bash
curl -X POST http://localhost:8000/auth/keys/rotate \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "password": "MiPassword123!@#",
    "reason": "Prueba de rotación manual"
  }'
```

### 2. Probar Verificación de Expiración

```bash
curl -X GET http://localhost:8000/auth/keys/check-expiration \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### 3. Probar Script de Verificación

```powershell
python rotate_keys_auto.py --check-only
```

---

## 📚 Referencias

- Documentación de criptografía: `/backend/app/utils/crypto.py`
- Configuración de políticas: `/backend/app/core/config.py`
- Modelos de base de datos: `/backend/app/models/models.py`
- Esquemas de validación: `/backend/app/schemas/schemas.py`

---

## 🆘 Solución de Problemas

### Error: "Claves vencidas desde hace X días"
**Solución:** Ejecutar rotación manual inmediatamente o esperar a la rotación automática.

### Error: "Contraseña incorrecta"
**Solución:** Verificar que estás usando la contraseña correcta para la rotación manual.

### Error: "Usuario no encontrado"
**Solución:** Verificar que el token JWT sea válido y el usuario exista en la base de datos.

### La tarea programada no se ejecuta
**Solución:** 
1. Verificar que el servicio "Task Scheduler" esté activo
2. Revisar los permisos de la tarea (debe ejecutarse como SYSTEM)
3. Verificar los logs en `key_rotation.log`

---

**Última actualización:** 6 de enero de 2026
