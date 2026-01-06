# Chat Seguro - Proyecto Final
## Seguridad en Sistemas Informáticos - UNAP

Sistema de chat en tiempo real con cifrado end-to-end (E2EE) implementando tecnologías de seguridad avanzadas.

---

## 🔐 Características de Seguridad

### Cifrado Implementado

#### Cifrado Asimétrico (RSA)
- **Tamaño de clave**: 2048/4096 bits
- **Padding**: OAEP con SHA-256
- **Uso**: Intercambio seguro de claves AES y firmas digitales
- **Algoritmo de firma**: RSA-PSS con SHA-256

#### Cifrado Simétrico (AES)
- **Tamaño de clave**: 256 bits
- **Modo de operación**: CBC (Cipher Block Chaining)
- **IV**: Vector de inicialización único por mensaje (128 bits)
- **Padding**: PKCS7

### Políticas de Seguridad

1. **Gestión de Claves**
   - Generación de claves RSA automática en registro
   - **✅ Rotación automática de claves cada 90 días** (implementado)
   - **✅ Rotación manual disponible vía API** (implementado)
   - **✅ Historial completo de rotaciones** (implementado)
   - Claves AES temporales por sesión (rotación cada 24 horas)
   - Almacenamiento seguro de claves públicas en BD
   - **✅ Tarea programada para rotación automática** (Windows Task Scheduler)

2. **Contraseñas**
   - Longitud mínima: 12 caracteres
   - Complejidad: Mayúsculas, minúsculas, números y caracteres especiales
   - Hash: Bcrypt con factor de trabajo 12
   - Bloqueo de cuenta: 5 intentos fallidos → 15 minutos

3. **Autenticación**
   - JWT con expiración corta (15 minutos access, 7 días refresh)
   - Autenticación de dos factores (TOTP) opcional
   - Rate limiting en login: 5 intentos/15 minutos
   - Sesiones rastreadas con auditoría

4. **Mensajes**
   - Cifrado end-to-end (E2EE)
   - Firma digital para autenticidad
   - Prevención de replay attacks con nonce único
   - Rate limiting: 100 mensajes/minuto

5. **Auditoría**
   - Registro de todos los intentos de autenticación
   - Log de rotación de claves
   - Registro de accesos y actividades sospechosas
   - Timestamps de todas las operaciones

## 🏗️ Arquitectura del Proyecto

```
Proyecto Final/
├── backend/                    # Servidor FastAPI
│   ├── app/
│   │   ├── api/               # Endpoints REST y WebSocket
│   │   │   ├── auth.py       # Autenticación, registro y rotación de claves
│   │   │   └── websocket.py  # Chat en tiempo real
│   │   ├── core/             # Configuración central
│   │   │   ├── config.py     # Variables de entorno
│   │   │   ├── security.py   # JWT y hashing
│   │   │   └── database.py   # Conexión PostgreSQL
│   │   ├── models/           # Modelos de base de datos
│   │   │   └── models.py     # SQLAlchemy models (incluye KeyRotationHistory)
│   │   ├── schemas/          # Validación de datos
│   │   │   └── schemas.py    # Pydantic schemas
│   │   ├── services/         # Lógica de negocio
│   │   │   └── auth_service.py # Servicio de autenticación y rotación
│   │   └── utils/            # Utilidades
│   │       └── crypto.py     # Módulo de cifrado
│   ├── main.py               # Aplicación FastAPI
│   ├── init_db.py            # Inicializar base de datos
│   ├── rotate_keys_auto.py   # ✅ Script de rotación automática
│   ├── test_rotation.py      # ✅ Script de prueba de rotación
│   ├── setup_rotation_task.ps1 # ✅ Configurar tarea programada
│   ├── requirements.txt      # Dependencias Python
│   └── .env                  # Variables de entorno
│
├── KEY_ROTATION_GUIDE.md     # ✅ Guía completa de rotación de claves
│
└── frontend/                  # Cliente Web
    ├── index.html            # Interfaz de usuario
    ├── styles.css            # Estilos CSS
    └── js/
        ├── config.js         # Configuración del cliente
        ├── crypto.js         # Cifrado client-side
        ├── api.js            # Cliente HTTP
        ├── websocket.js      # Gestor WebSocket
        └── app.js            # Lógica de la aplicación
```

## 🚀 Instalación y Configuración

### Requisitos Previos
- Python 3.11+
- PostgreSQL 16+
- Navegador web moderno (Chrome, Firefox, Edge)

### 1. Configurar Backend

```powershell
# Navegar a la carpeta backend
cd backend

# Crear entorno virtual
python -m venv venv

# Activar entorno virtual
.\venv\Scripts\Activate.ps1

# Instalar dependencias
pip install -r requirements.txt

# Configurar base de datos
# Editar .env con tus credenciales de PostgreSQL

# Inicializar base de datos
python init_db.py

# Verificar base de datos
python verify_db.py
```

### 2. Ejecutar Servidor

```powershell
# Desde la carpeta backend
python main.py

# El servidor estará disponible en:
# http://localhost:8000
# WebSocket: ws://localhost:8000/ws/chat
```

### 3. Abrir Cliente Web

```powershell
# Opción 1: Servidor HTTP simple con Python
cd frontend
python -m http.server 8080

# Opción 2: Abrir directamente index.html en el navegador
# O usar Live Server de VS Code
```

```bash
POST /auth/register
Content-Type: application/json

{
  "username": "usuario1",
  "email": "usuario1@example.com",
  "password": "MiPassword123!@#"
}
```

### Login

```bash
POST /auth/login
Content-Type: application/json

{
  "username": "usuario1",
  "password": "MiPassword123!@#",
  "totp_code": "123456"  # Opcional, solo si 2FA está habilitado
}
```

### Obtener Clave Pública de Usuario

```bash
GET /auth/users/public-key/{user_id}
Authorization: Bearer <access_token>
```

### Rotar Claves RSA (Manual)

```bash
POST /auth/keys/rotate
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "password": "MiPassword123!@#",
  "reason": "Rotación manual por actualización de seguridad"
}
```

### Verificar Estado de Claves

```bash
GET /auth/keys/check-expiration
Authorization: Bearer <access_token>
```

### Ver Historial de Rotaciones

```bash
GET /auth/keys/rotation-history?limit=10
Authorization: Bearer <access_token>
```

### Conectar a WebSocket

```javascript
const token = "tu_access_token";
const ws = new WebSocket(`ws://localhost:8000/ws/chat?token=${token}`);

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log("Mensaje recibido:", data);
};
```

### Enviar Mensaje Cifrado

```javascript
// 1. Obtener clave pública del destinatario
// 2. Generar clave AES temporal
// 3. Cifrar mensaje con AES
// 4. Cifrar clave AES con RSA del destinatario
// 5. Firmar mensaje con tu clave privada RSA

const message = {
  type: "message",
  recipient_id: 2,
  encrypted_data: {
    encrypted_message: "...",  // Base64
    encrypted_key: "...",      // Base64
    iv: "...",                 // Base64
    signature: "...",          // Base64
    timestamp: "2026-01-05T..."
  }
};

ws.send(JSON.stringify(message));
```

## 🔧 Tecnologías Utilizadas

### Backend
- **FastAPI**: Framework web asíncrono
- **SQLAlchemy**: ORM para PostgreSQL
- **Pydantic**: Validación de datos
- **Uvicorn**: Servidor ASGI

### Seguridad
- **cryptography**: Cifrado RSA y AES
- **python-jose**: JWT
- **passlib + bcrypt**: Hashing de contraseñas
- **pyotp**: Autenticación 2FA (TOTP)
- **slowapi**: Rate limiting

### Base de Datos
- **PostgreSQL**: Base de datos principal
- **Redis**: Caché y sesiones (opcional)

## 📊 Flujo de Cifrado Híbrido

```
1. Usuario A quiere enviar mensaje a Usuario B
   
2. Cliente A:
   a) Genera clave AES-256 aleatoria
   b) Cifra mensaje con AES-CBC
   c) Obtiene clave pública RSA de B
   d) Cifra clave AES con clave pública de B
   e) Firma mensaje con su clave privada RSA
   
3. Servidor:
   a) Recibe mensaje cifrado + clave AES cifrada + firma
   b) Almacena en BD (todo cifrado)
   c) Reenvía a Cliente B si está online
   
4. Cliente B:
   a) Recibe mensaje cifrado
   b) Descifra clave AES con su clave privada RSA
   c) Descifra mensaje con clave AES
   d) Verifica firma con clave pública de A
   e) Muestra mensaje si firma es válida
```

## 🔄 Rotación de Claves

### Configuración Automática

```powershell
# Configurar tarea programada (ejecutar con permisos de administrador)
cd backend
.\setup_rotation_task.ps1
```

La tarea ejecutará automáticamente la rotación diaria a las 2:00 AM.

### Rotación Manual

```powershell
# Verificar claves vencidas sin rotar
python rotate_keys_auto.py --check-only

# Ejecutar rotación automática
python rotate_keys_auto.py
```

### Prueba del Sistema

```powershell
# Ejecutar prueba completa de rotación
python test_rotation.py
```

**📖 Documentación completa:** Ver [KEY_ROTATION_GUIDE.md](KEY_ROTATION_GUIDE.md)

## ️ Medidas de Protección

### Contra Ataques de Fuerza Bruta
- Rate limiting en endpoints de autenticación
- Bloqueo temporal de cuenta tras intentos fallidos
- Contraseñas con alta entropía

### Contra Replay Attacks
- Nonce único por mensaje
- Timestamps en mensajes
- Expiración de tokens JWT

### Contra Man-in-the-Middle
- Cifrado end-to-end
- Firmas digitales para autenticidad
- HTTPS en producción (configurar con reverse proxy)

### Contra Timing Attacks
- Padding seguro (OAEP, PSS)
- Comparaciones de tiempo constante en verificaciones

## 📝 Notas de Seguridad

⚠️ **IMPORTANTE**: Este es un proyecto educativo. Para producción:

1. Usar HTTPS/WSS (certificados SSL/TLS)
2. Implementar HashiCorp Vault o AWS KMS para gestión de claves
3. Configurar firewall y segmentación de red
4. Implementar backup cifrado de base de datos
5. Usar HSM (Hardware Security Module) para claves críticas
6. Auditoría de seguridad profesional
7. Implementar HSTS, CSP y otros headers de seguridad
8. Rotación automática de claves con calendario definido

## 👥 Equipo

Proyecto final - Curso de Seguridad en Sistemas Informáticos
Universidad Nacional del Altiplano - VIII Semestre

## 📄 Licencia

Este proyecto es con fines educativos.
