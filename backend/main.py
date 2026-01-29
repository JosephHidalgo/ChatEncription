"""
Aplicación principal de FastAPI.
Configura rutas, middleware, CORS y ciclo de vida.
"""
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import AsyncSession
import json

from app.core.config import settings
from app.core.database import init_db, close_db, get_db
from app.api import auth, websocket
from app.api import groups
from app.api.websocket import manager, get_user_from_websocket_token, handle_websocket_message
from loguru import logger


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Maneja el ciclo de vida de la aplicación.
    Inicializa y cierra recursos.
    """
    # Startup
    logger.info("Iniciando aplicación...")
    logger.info(f"Creando tablas de base de datos...")
    await init_db()
    logger.info("Aplicación iniciada correctamente")
    
    yield
    
    # Shutdown
    logger.info("Cerrando aplicación...")
    await close_db()
    logger.info("Aplicación cerrada")


# Crear aplicación FastAPI
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Sistema de chat seguro con cifrado end-to-end (RSA + AES)",
    lifespan=lifespan
)

# Configurar CORS para permitir acceso desde red local
# En desarrollo, permite tanto HTTP como HTTPS
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        # Localhost
        "http://localhost:5173",
        "https://localhost:5173",
        "http://127.0.0.1:5173",
        "https://127.0.0.1:5173",
        "http://10.236.150.102:5173",
        "https://10.236.150.102:5173",
        # Permite cualquier IP de red local (10.x.x.x)
        "http://10.*.*.*:5173",
        "https://10.*.*.*:5173",
        
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
)

# Incluir routers
app.include_router(auth.router)
app.include_router(groups.router)


# ===================== WEBSOCKET ENDPOINT =====================

@app.websocket("/ws/chat")
async def websocket_chat_endpoint(
    websocket: WebSocket,
    token: str = Query(...),
    db: AsyncSession = Depends(get_db)
):
    """
    Endpoint WebSocket para chat en tiempo real.
    
    Políticas de Seguridad:
    - Requiere autenticación por token JWT
    - Mensajes cifrados end-to-end
    - Límite de 3 conexiones simultáneas por usuario
    
    Parámetros:
        token: Token JWT para autenticación (query param)
    """
    try:
        # Autenticar usuario
        current_user = await get_user_from_websocket_token(token, db)
        
        # Verificar límite de conexiones (política de seguridad)
        if current_user.id in manager.active_connections:
            if len(manager.active_connections[current_user.id]) >= 3:
                await websocket.close(code=1008, reason="Límite de conexiones excedido")
                return
        
        # Conectar
        await manager.connect(websocket, current_user.id)
        
        # Enviar confirmación de conexión
        await websocket.send_json({
            'type': 'connected',
            'user_id': current_user.id,
            'username': current_user.username,
            'message': 'Conectado al chat seguro'
        })
        
        # Notificar a otros usuarios que este usuario está online
        await manager.broadcast({
            'type': 'user_online',
            'user_id': current_user.id,
            'username': current_user.username
        }, exclude_user=current_user.id)
        
        # Loop de recepción de mensajes
        while True:
            # Recibir mensaje
            data = await websocket.receive_text()
            message_data = json.loads(data)
            
            # Procesar mensaje
            await handle_websocket_message(
                websocket,
                current_user,
                message_data,
                db
            )
    
    except WebSocketDisconnect:
        # Usuario se desconectó
        manager.disconnect(websocket, current_user.id)
        
        # Notificar a otros usuarios
        await manager.broadcast({
            'type': 'user_offline',
            'user_id': current_user.id,
            'username': current_user.username
        }, exclude_user=current_user.id)
        
        logger.info(f"WebSocket desconectado: Usuario {current_user.id}")
    
    except Exception as e:
        logger.error(f"Error en WebSocket: {e}")
        manager.disconnect(websocket, current_user.id if 'current_user' in locals() else None)
        await websocket.close(code=1011, reason="Error interno del servidor")


# ===================== ENDPOINTS DE MENSAJES =====================

@app.get("/api/messages/history/{recipient_id}")
async def get_message_history(
    recipient_id: int,
    limit: int = 50,
    current_user = Depends(auth.get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Obtiene el historial de mensajes con un usuario específico.
    Los mensajes se devuelven cifrados.
    
    Args:
        recipient_id: ID del otro usuario
        limit: Número máximo de mensajes (default 50)
    """
    from sqlalchemy import select, or_, and_
    from app.models.models import Message
    import json
    
    stmt = select(Message).where(
        or_(
            and_(Message.sender_id == current_user.id, Message.recipient_id == recipient_id),
            and_(Message.sender_id == recipient_id, Message.recipient_id == current_user.id)
        )
    ).order_by(Message.timestamp.desc()).limit(limit)
    
    result = await db.execute(stmt)
    messages = result.scalars().all()
    
    message_list = []
    for msg in reversed(messages):
        msg_dict = {
            'id': msg.id,
            'sender_id': msg.sender_id,
            'recipient_id': msg.recipient_id,
            'encrypted_content': msg.encrypted_content,
            'encrypted_aes_key': msg.encrypted_aes_key,
            'iv': msg.iv,
            'signature': msg.signature,
            'timestamp': msg.timestamp.isoformat(),
            'is_read': msg.is_read
        }
        
        # Extraer datos del emisor desde encrypted_data JSON si existen
        if msg.encrypted_data:
            try:
                encrypted_data = json.loads(msg.encrypted_data)
                if 'sender_encrypted_message' in encrypted_data:
                    msg_dict['sender_encrypted_message'] = encrypted_data['sender_encrypted_message']
                    msg_dict['sender_encrypted_key'] = encrypted_data['sender_encrypted_key']
                    msg_dict['sender_iv'] = encrypted_data['sender_iv']
            except json.JSONDecodeError:
                pass
        
        message_list.append(msg_dict)
    
    return {'messages': message_list}


# ===================== HEALTH CHECK =====================

@app.get("/health")
async def health_check():
    """
    Endpoint de verificación de salud del servicio.
    """
    return {
        "status": "healthy",
        "app_name": settings.APP_NAME,
        "version": settings.APP_VERSION
    }


@app.get("/")
async def root():
    """
    Endpoint raíz de la API.
    """
    return {
        "message": f"Bienvenido a {settings.APP_NAME}",
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": "/health"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )
