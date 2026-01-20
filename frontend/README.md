# SecureChat Frontend (React + Vite)

Frontend moderno de SecureChat migrado a React con Vite.

## 🚀 Características

- ⚛️ **React 18** con Hooks
- ⚡ **Vite** para desarrollo rápido
- 🔐 **Cifrado End-to-End** (RSA + AES)
- 🔌 **WebSocket** en tiempo real
- 🎨 **Diseño responsive** inspirado en WhatsApp
- 🔑 **Autenticación 2FA**
- 🔄 **Rotación de claves**

## 📁 Estructura del Proyecto

```
src/
├── components/          # Componentes React
│   ├── Auth/           # Login, Register, AuthPage
│   ├── Chat/           # Sidebar, ChatArea, ChatPage
│   └── Common/         # Modales reutilizables
├── contexts/           # Context API (AuthContext)
├── services/           # API y WebSocket
├── utils/              # Utilidades (config, crypto)
└── styles.css          # Estilos globales
```

## 🛠️ Instalación

```bash
# Instalar dependencias
npm install

# Modo desarrollo
npm run dev

# Build para producción
npm run build
```

## 🌐 Desarrollo

El servidor de desarrollo de Vite corre en `http://localhost:5173` por defecto.

Para conectarse al backend:
1. Asegúrate de que el backend esté corriendo en `http://localhost:8000`
2. Inicia el frontend: `npm run dev`
3. Abre `http://localhost:5173`

## 📝 Migración de Vanilla JS a React

### Ventajas:

✅ **Mejor organización**: Código modular y reutilizable  
✅ **Rendimiento**: Virtual DOM y optimizaciones de React  
✅ **Mantenibilidad**: Componentes autocontenidos  
✅ **Escalabilidad**: Fácil agregar nuevas features  
✅ **Developer Experience**: Hot Module Replacement (HMR)  

## 📄 Licencia

Proyecto educativo - UNAP VIII Semestre - 2026
