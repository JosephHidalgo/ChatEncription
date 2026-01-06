# Chat Seguro - Frontend

Cliente web para el sistema de chat seguro con cifrado end-to-end.

## 🎨 Características

- **Interfaz moderna**: Diseño responsivo y atractivo
- **Cifrado client-side**: Web Crypto API para E2EE
- **WebSocket en tiempo real**: Mensajes instantáneos
- **Notificaciones**: Toast notifications para feedback
- **Indicadores de estado**: Online/offline, escribiendo...
- **Modales**: Configuración, información de cifrado
- **Animaciones**: Transiciones suaves

## 📁 Estructura

```
frontend/
├── index.html          # Interfaz principal
├── styles.css          # Estilos CSS
└── js/
    ├── config.js       # Configuración (URLs, constantes)
    ├── crypto.js       # Módulo de cifrado (Web Crypto API)
    ├── api.js          # Cliente HTTP para REST API
    ├── websocket.js    # Gestor de WebSocket
    └── app.js          # Lógica principal de la aplicación
```

## 🚀 Uso

### Opción 1: Servidor HTTP con Python

```powershell
cd frontend
python -m http.server 8080
```

Luego abrir: http://localhost:8080

### Opción 2: Live Server (VS Code)

1. Instalar extensión "Live Server"
2. Click derecho en `index.html`
3. Seleccionar "Open with Live Server"

### Opción 3: Abrir directamente

Simplemente abrir `index.html` en el navegador (puede tener limitaciones de CORS)

## 🔧 Configuración

Editar [js/config.js](js/config.js) para cambiar:

```javascript
const CONFIG = {
    API_URL: 'http://localhost:8000',      // URL del backend
    WS_URL: 'ws://localhost:8000/ws/chat',  // URL del WebSocket
    RSA_KEY_SIZE: 2048,                     // Tamaño de clave RSA
    AES_KEY_SIZE: 256                       // Tamaño de clave AES
};
```

## 📱 Funcionalidades

### Autenticación

- **Registro**: Crear nueva cuenta con validación de contraseña
- **Login**: Iniciar sesión con 2FA opcional
- **Logout**: Cerrar sesión y limpiar datos

### Chat

- **Seleccionar usuario**: Click en usuario de la lista
- **Enviar mensajes**: Escribir y presionar Enter o click en enviar
- **Ver historial**: Cargar conversaciones anteriores
- **Indicador de escritura**: Ver cuando alguien está escribiendo

### Seguridad

- **Cifrado E2EE**: Todos los mensajes cifrados antes de enviar
- **Verificación de firmas**: Validar autenticidad de mensajes
- **2FA**: Configurar autenticación de dos factores
- **Rotación de claves**: Generar nuevas claves RSA

## 🎨 Pantallas

### Pantalla de Autenticación

- Formulario de login
- Formulario de registro
- Tabs para alternar entre ambos
- Animación de entrada (slideUp)

### Pantalla de Chat

**Sidebar (Lista de usuarios)**
- Avatar con inicial
- Nombre de usuario
- Estado (online/offline)
- Badge 2FA si está habilitado

**Área de chat**
- Header con nombre del destinatario
- Contenedor de mensajes
- Burbujas de mensajes (enviados/recibidos)
- Verificación de firma
- Input de mensaje
- Botón de envío

**Modales**
- Configuración (2FA, rotación de claves)
- Información de cifrado

**Notificaciones**
- Toast messages (success, error, info, warning)

## 🔐 Módulo de Cifrado

El módulo `crypto.js` implementa:

### Funciones principales

```javascript
// Generar clave AES
await CryptoModule.generateAESKey()

// Cifrar con AES-256-CBC
await CryptoModule.encryptAES(message, key, iv)

// Descifrar
await CryptoModule.decryptAES(encryptedData, key, iv)

// Crear sobre cifrado (híbrido)
await CryptoModule.createSecureEnvelope(message, publicKeyPEM)

// Abrir sobre cifrado
await CryptoModule.openSecureEnvelope(envelope, privateKeyPEM, senderPublicKeyPEM)

// Firmar mensaje
await CryptoModule.sign(message, privateKeyPEM)

// Verificar firma
await CryptoModule.verify(message, signature, publicKeyPEM)
```

### Flujo de cifrado

1. Generar clave AES temporal
2. Cifrar mensaje con AES-CBC
3. Cifrar clave AES con RSA del destinatario
4. Firmar mensaje cifrado con RSA del emisor
5. Crear envelope con todos los componentes

## 🎯 Eventos y Flujo

### Flujo de Registro

1. Usuario completa formulario
2. Validación client-side
3. POST `/auth/register`
4. Mostrar toast de confirmación
5. Cambiar a formulario de login

### Flujo de Login

1. Usuario ingresa credenciales
2. POST `/auth/login`
3. Guardar tokens en localStorage
4. Cargar usuario actual
5. Conectar WebSocket
6. Mostrar pantalla de chat

### Flujo de Envío de Mensaje

1. Usuario escribe mensaje
2. Click en enviar o Enter
3. Cifrar mensaje con clave pública del destinatario
4. Enviar por WebSocket
5. Mostrar mensaje en pantalla
6. Limpiar input

### Flujo de Recepción de Mensaje

1. WebSocket recibe mensaje
2. Descifrar con clave privada
3. Verificar firma digital
4. Mostrar mensaje con indicador de verificación
5. Marcar como leído

## 🛠️ Tecnologías

- **HTML5**: Estructura semántica
- **CSS3**: Estilos modernos, variables CSS, flexbox
- **JavaScript (ES6+)**: Async/await, modules, clases
- **Web Crypto API**: Cifrado nativo del navegador
- **WebSocket API**: Comunicación bidireccional
- **Fetch API**: Peticiones HTTP
- **Font Awesome**: Iconos

## 📊 Almacenamiento Local

El cliente guarda en localStorage:

```javascript
{
  "access_token": "JWT access token",
  "refresh_token": "JWT refresh token",
  "private_key_rsa": "Clave privada RSA (PEM)",
  "user_id": "ID del usuario",
  "username": "Nombre de usuario"
}
```

⚠️ **Nota**: En producción, usar almacenamiento más seguro (e.g., IndexedDB cifrado)

## 🎨 Personalización

### Cambiar colores

Editar variables CSS en `styles.css`:

```css
:root {
    --primary-color: #667eea;
    --secondary-color: #764ba2;
    --success-color: #10b981;
    --error-color: #ef4444;
    /* ... más colores */
}
```

### Ajustar animaciones

```css
.message {
    animation: slideIn 0.3s ease-out;
}

@keyframes slideIn {
    from { transform: translateY(20px); opacity: 0; }
    to { transform: translateY(0); opacity: 1; }
}
```

## 🐛 Debugging

### Consola del navegador

Abrir DevTools (F12) y revisar:
- **Console**: Logs y errores
- **Network**: Peticiones HTTP/WebSocket
- **Application > Local Storage**: Datos guardados

### Logs útiles

El cliente muestra logs de:
- Conexión WebSocket
- Mensajes recibidos/enviados
- Errores de cifrado
- Eventos de autenticación

## 🔒 Consideraciones de Seguridad

1. **HTTPS**: En producción usar HTTPS
2. **Content Security Policy**: Configurar CSP headers
3. **localStorage**: Considerar alternativas más seguras
4. **Sanitización**: Validar y limpiar input del usuario
5. **CORS**: Configurar correctamente en backend

## 📝 Notas

- Compatible con navegadores modernos (Chrome 90+, Firefox 88+, Edge 90+)
- Requiere soporte de Web Crypto API
- WebSocket debe estar disponible

---

**¡Cliente web completamente funcional!** 🚀
