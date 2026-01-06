// Aplicación principal del chat seguro
let currentUser = null;
let currentRecipient = null;
let typingTimeout = null;
let wsManager = null;

/**
 * Generar color aleatorio para avatar
 */
function getRandomGradient(seed) {
    // Colores base para degradados
    const gradients = [
        ['#667eea', '#764ba2'],
        ['#f093fb', '#f5576c'],
        ['#4facfe', '#00f2fe'],
        ['#43e97b', '#38f9d7'],
        ['#fa709a', '#fee140'],
        ['#30cfd0', '#330867'],
        ['#a8edea', '#fed6e3'],
        ['#ff9a56', '#ff6a88'],
        ['#fbc2eb', '#a6c1ee'],
        ['#fdcbf1', '#e6dee9'],
        ['#a1c4fd', '#c2e9fb'],
        ['#ffecd2', '#fcb69f'],
        ['#ff6e7f', '#bfe9ff'],
        ['#e0c3fc', '#8ec5fc'],
        ['#f77062', '#fe5196'],
        ['#21d4fd', '#b721ff'],
        ['#08aeea', '#2af598'],
        ['#ff0844', '#ffb199'],
    ];
    
    // Usar el ID del usuario como seed para que siempre tenga el mismo color
    const index = seed % gradients.length;
    return `linear-gradient(135deg, ${gradients[index][0]}, ${gradients[index][1]})`;
}

/**
 * Inicializar la aplicación
 */
async function initApp() {
    DEBUG.info('Iniciando aplicación de chat seguro...');
    DEBUG.info('API URL: ' + CONFIG.API_URL);
    DEBUG.info('WS URL: ' + CONFIG.WS_URL);
    
    // Verificar token existente
    const token = localStorage.getItem(CONFIG.STORAGE_KEYS.ACCESS_TOKEN);
    DEBUG.info('Token existente: ' + (token ? 'SÍ (' + token.substring(0, 30) + '...)' : 'NO'));
    
    if (token) {
        try {
            // Intentar cargar usuario actual
            DEBUG.info('Cargando usuario actual...');
            currentUser = await API.getCurrentUser();
            DEBUG.success('Usuario cargado: ' + currentUser.username);
            showChatScreen();
        } catch (error) {
            DEBUG.error('Token inválido: ' + error.message);
            localStorage.clear();
            showAuthScreen();
        }
    } else {
        showAuthScreen();
    }
    
    // Configurar event listeners
    setupEventListeners();
}

/**
 * Configurar todos los event listeners
 */
function setupEventListeners() {
    // Tabs de autenticación - Nuevos botones
    const tabLogin = document.getElementById('tab-login');
    const tabRegister = document.getElementById('tab-register');
    
    if (tabLogin) {
        tabLogin.addEventListener('click', () => {
            // Activar tab de login
            tabLogin.classList.add('active');
            tabRegister.classList.remove('active');
            
            // Mostrar formulario de login
            document.getElementById('login-form').classList.add('active');
            document.getElementById('register-form').classList.remove('active');
        });
    }
    
    if (tabRegister) {
        tabRegister.addEventListener('click', () => {
            // Activar tab de registro
            tabRegister.classList.add('active');
            tabLogin.classList.remove('active');
            
            // Mostrar formulario de registro
            document.getElementById('register-form').classList.add('active');
            document.getElementById('login-form').classList.remove('active');
        });
    }
    
    // Tabs de autenticación - Botones antiguos (por compatibilidad)
    const showLoginBtn = document.getElementById('show-login');
    const showRegisterBtn = document.getElementById('show-register');
    
    if (showLoginBtn) showLoginBtn.addEventListener('click', () => showLoginForm());
    if (showRegisterBtn) showRegisterBtn.addEventListener('click', () => showRegisterForm());
    
    // Formularios
    const loginForm = document.getElementById('login-form');
    const registerForm = document.getElementById('register-form');
    
    if (loginForm) loginForm.addEventListener('submit', handleLogin);
    if (registerForm) registerForm.addEventListener('submit', handleRegister);
    
    // Chat - Solo configurar si los elementos existen
    const sendBtn = document.getElementById('send-btn');
    const messageInput = document.getElementById('message-input');
    
    if (sendBtn) sendBtn.addEventListener('click', sendMessage);
    if (messageInput) {
        messageInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                sendMessage();
            }
        });
        messageInput.addEventListener('input', handleTyping);
    }
    
    // Botones de acciones
    const settingsBtn = document.getElementById('settings-btn');
    const logoutBtn = document.getElementById('logout-btn');
    const encryptionInfoBtn = document.getElementById('encryption-info-btn');
    
    if (settingsBtn) settingsBtn.addEventListener('click', showSettingsModal);
    if (logoutBtn) logoutBtn.addEventListener('click', handleLogout);
    if (encryptionInfoBtn) encryptionInfoBtn.addEventListener('click', showEncryptionInfo);
    
    // Modales
    document.querySelectorAll('.modal-close').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const modal = e.target.closest('.modal');
            if (modal) closeModal(modal.id);
        });
    });
    
    // Cerrar modal al hacer click fuera
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                closeModal(modal.id);
            }
        });
    });
    
    // 2FA - Estos se configurarán cuando se abra el modal
    const enable2FABtn = document.getElementById('enable-2fa-btn');
    const rotateKeysBtn = document.getElementById('rotate-keys-btn');
    
    if (enable2FABtn) enable2FABtn.addEventListener('click', setup2FA);
    if (rotateKeysBtn) rotateKeysBtn.addEventListener('click', rotateKeys);
    
    // WebSocket events se configuran en showChatScreen() cuando se inicializa wsManager
}

/**
 * Mostrar pantalla de autenticación
 */
function showAuthScreen() {
    document.getElementById('auth-screen').classList.add('active');
    document.getElementById('chat-screen').classList.remove('active');
}

/**
 * Mostrar pantalla de chat
 */
async function showChatScreen() {
    document.getElementById('auth-screen').classList.remove('active');
    document.getElementById('chat-screen').classList.add('active');
    
    // Actualizar información del usuario
    document.getElementById('current-username').textContent = currentUser.username;
    
    // Actualizar avatar del usuario actual con degradado
    const userAvatar = document.querySelector('.sidebar-header .user-avatar');
    if (userAvatar) {
        userAvatar.style.background = getRandomGradient(currentUser.id);
        userAvatar.innerHTML = currentUser.username[0].toUpperCase();
    }
    
    // Cargar lista de usuarios
    await loadUsers();
    
    // Inicializar WebSocket Manager
    wsManager = new WebSocketManager();
    
    // Configurar eventos de WebSocket
    wsManager.on('message', handleIncomingMessage);
    wsManager.on('typing', handleTypingNotification);
    wsManager.on('online', updateOnlineUsers);
    wsManager.on('offline', updateOnlineUsers);
    
    // Conectar WebSocket
    wsManager.connect();
    
    // Solicitar usuarios en línea
    setTimeout(() => wsManager.requestOnlineUsers(), 1000);
}

/**
 * Mostrar formulario de login
 */
function showLoginForm() {
    document.getElementById('show-login').classList.add('active');
    document.getElementById('show-register').classList.remove('active');
    document.getElementById('login-form').style.display = 'block';
    document.getElementById('register-form').style.display = 'none';
}

/**
 * Mostrar formulario de registro
 */
function showRegisterForm() {
    document.getElementById('show-register').classList.add('active');
    document.getElementById('show-login').classList.remove('active');
    document.getElementById('register-form').style.display = 'block';
    document.getElementById('login-form').style.display = 'none';
}

/**
 * Manejar login
 */
async function handleLogin(e) {
    e.preventDefault();
    
    const username = document.getElementById('login-username').value;
    const password = document.getElementById('login-password').value;
    const totp = document.getElementById('login-totp').value || null;
    
    const submitBtn = e.target.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Iniciando sesión...';
    
    try {
        const response = await API.login(username, password, totp);
        
        // Guardar tokens
        localStorage.setItem(CONFIG.STORAGE_KEYS.ACCESS_TOKEN, response.access_token);
        localStorage.setItem(CONFIG.STORAGE_KEYS.REFRESH_TOKEN, response.refresh_token);
        
        // Guardar claves privadas (en producción usar almacenamiento más seguro)
        localStorage.setItem(CONFIG.STORAGE_KEYS.PRIVATE_KEY, response.private_key_rsa);
        
        // Cargar usuario
        currentUser = await API.getCurrentUser();
        
        // Guardar ID de usuario para cifrado
        localStorage.setItem(CONFIG.STORAGE_KEYS.USER_ID, currentUser.id.toString());
        DEBUG.info('Usuario ID guardado: ' + currentUser.id);
        
        showToast('success', 'Login exitoso', `Bienvenido ${currentUser.username}`);
        showChatScreen();
        
    } catch (error) {
        console.error('Error en login:', error);
        showToast('error', 'Error', error.message || 'Error al iniciar sesión');
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Iniciar Sesión';
    }
}

/**
 * Manejar registro
 */
async function handleRegister(e) {
    e.preventDefault();
    
    const username = document.getElementById('register-username').value;
    const email = document.getElementById('register-email').value;
    const password = document.getElementById('register-password').value;
    const confirmPassword = document.getElementById('register-confirm').value;
    
    // Validar contraseñas
    if (password !== confirmPassword) {
        showToast('error', 'Error', 'Las contraseñas no coinciden');
        return;
    }
    
    const submitBtn = e.target.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.textContent = 'Registrando...';
    
    try {
        await API.register(username, email, password);
        
        showToast('success', 'Registro exitoso', 'Ahora puedes iniciar sesión');
        showLoginForm();
        
        // Limpiar formulario
        e.target.reset();
        
    } catch (error) {
        console.error('Error en registro:', error);
        showToast('error', 'Error', error.message || 'Error al registrar usuario');
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = 'Registrarse';
    }
}

/**
 * Cargar lista de usuarios
 */
async function loadUsers() {
    try {
        const users = await API.getUsers();
        const userList = document.getElementById('users-list');
        
        if (!userList) {
            console.error('Elemento users-list no encontrado');
            return;
        }
        
        userList.innerHTML = '';
        
        users.forEach(user => {
            if (user.id === currentUser.id) return; // No mostrar usuario actual
            
            const userItem = document.createElement('div');
            userItem.className = 'user-item';
            userItem.dataset.userId = user.id;
            
            userItem.innerHTML = `
                <div class="user-avatar" style="background: ${getRandomGradient(user.id)}">${user.username[0].toUpperCase()}</div>
                <div class="user-info">
                    <div class="user-name">${user.username}</div>
                    <div class="user-status">
                        <span class="status-indicator ${user.is_online ? 'online' : 'offline'}"></span>
                        <span class="status-text">${user.is_online ? 'En línea' : 'Desconectado'}</span>
                    </div>
                </div>
                ${user.totp_enabled ? '<span class="badge">2FA</span>' : ''}
            `;
            
            userItem.addEventListener('click', () => selectUser(user));
            userList.appendChild(userItem);
        });
        
    } catch (error) {
        console.error('Error cargando usuarios:', error);
        showToast('error', 'Error', 'No se pudo cargar la lista de usuarios');
    }
}

/**
 * Seleccionar usuario para chatear
 */
async function selectUser(user) {
    currentRecipient = user;
    
    // Actualizar UI
    document.querySelectorAll('.user-item').forEach(item => {
        item.classList.remove('active');
    });
    
    const selectedItem = document.querySelector(`[data-user-id="${user.id}"]`);
    if (selectedItem) selectedItem.classList.add('active');
    
    // Actualizar header del chat
    const chatUsername = document.getElementById('chat-username');
    if (chatUsername) chatUsername.textContent = user.username;
    
    // Actualizar avatar del chat header con degradado
    const chatAvatar = document.querySelector('.chat-header .user-avatar');
    if (chatAvatar) {
        chatAvatar.style.background = getRandomGradient(user.id);
        chatAvatar.innerHTML = user.username[0].toUpperCase();
    }
    
    // Responsive: Ocultar sidebar en móviles cuando se selecciona un chat
    const sidebar = document.querySelector('.sidebar');
    const chatArea = document.querySelector('.chat-area');
    const backBtn = document.querySelector('.btn-back-mobile');
    
    if (window.innerWidth <= 768) {
        if (sidebar) sidebar.classList.add('hide-mobile');
        if (chatArea) chatArea.classList.add('show-mobile');
        if (backBtn) backBtn.style.display = 'flex';
    }
    
    // Mostrar área de chat y ocultar placeholder
    const placeholder = document.querySelector('.no-chat-selected');
    const messagesDiv = document.getElementById('messages');
    const messageInputContainer = document.getElementById('message-input-container');
    
    if (placeholder) placeholder.style.display = 'none';
    if (messagesDiv) messagesDiv.style.display = 'flex';
    if (messageInputContainer) messageInputContainer.style.display = 'block';
    
    // Cargar historial de mensajes
    await loadMessageHistory(user.id);
    
    // Habilitar input
    const messageInput = document.getElementById('message-input');
    const sendBtn = document.getElementById('send-btn');
    
    if (messageInput) {
        messageInput.disabled = false;
        messageInput.focus(); // Dar foco al input
    }
    if (sendBtn) sendBtn.disabled = false;
}

/**
 * Cargar historial de mensajes
 */
async function loadMessageHistory(recipientId) {
    try {
        DEBUG.info('Cargando historial de mensajes con usuario: ' + recipientId);
        const messages = await API.getMessageHistory(recipientId);
        const container = document.getElementById('messages');
        
        if (!container) {
            console.error('Contenedor de mensajes no encontrado');
            return;
        }
        
        container.innerHTML = '';
        
        if (!messages || messages.length === 0) {
            container.innerHTML = '<div style="text-align: center; padding: 20px; color: #999;">No hay mensajes previos. ¡Inicia la conversación!</div>';
            return;
        }
        
        DEBUG.info('Mensajes encontrados: ' + messages.length);
        
        // Obtener mi ID
        let myUserId = parseInt(localStorage.getItem(CONFIG.STORAGE_KEYS.USER_ID));
        if (isNaN(myUserId) && currentUser) {
            myUserId = currentUser.id;
        }
        
        // Descifrar y mostrar cada mensaje
        for (const msg of messages) {
            try {
                // Verificar si hay datos cifrados
                if (msg.encrypted_data) {
                    DEBUG.crypto('Descifrando mensaje del historial...');
                    
                    // Asegurar que el envelope tenga los IDs
                    const envelope = msg.encrypted_data;
                    envelope.sender_id = msg.sender_id;
                    envelope.recipient_id = msg.recipient_id;
                    
                    const decrypted = await CryptoModule.openSecureEnvelope(
                        envelope,
                        null,  // privateKey no se usa
                        null,  // senderPublicKey no se usa
                        myUserId
                    );
                    
                    displayMessage({
                        content: decrypted.message,
                        sender_id: msg.sender_id,
                        timestamp: msg.timestamp,
                        signatureValid: decrypted.signatureValid
                    });
                } else {
                    // Mensaje sin cifrar (fallback)
                    displayMessage({
                        content: msg.content || '[Mensaje no disponible]',
                        sender_id: msg.sender_id,
                        timestamp: msg.timestamp
                    });
                }
            } catch (decryptError) {
                DEBUG.error('Error descifrando mensaje del historial: ' + decryptError.message);
                // Mostrar mensaje como no descifrable
                displayMessage({
                    content: '🔒 [Mensaje cifrado - no se puede descifrar]',
                    sender_id: msg.sender_id,
                    timestamp: msg.timestamp,
                    isError: true
                });
            }
        }
        
        // Scroll al final
        setTimeout(() => {
            container.scrollTop = container.scrollHeight;
        }, 100);
        
        DEBUG.success('Historial cargado correctamente');
        
    } catch (error) {
        console.error('Error cargando historial:', error);
        DEBUG.error('Error cargando historial: ' + error.message);
    }
}

/**
 * Enviar mensaje
 */
async function sendMessage(event) {
    if (event) event.preventDefault();
    
    const input = document.getElementById('message-input');
    const message = input.value.trim();
    
    if (!message || !currentRecipient) {
        DEBUG.warn('No hay mensaje o destinatario');
        return;
    }
    
    try {
        DEBUG.info('=== ENVIANDO MENSAJE ===');
        DEBUG.info('Mensaje: ' + message);
        DEBUG.info('Destinatario ID: ' + currentRecipient.id);
        DEBUG.info('Destinatario: ' + currentRecipient.username);
        
        // Enviar por WebSocket
        await wsManager.sendChatMessage(currentRecipient.id, message);
        
        DEBUG.success('Mensaje procesado, mostrando en UI...');
        
        // Mostrar mensaje enviado
        await displayMessage({
            sender_id: currentUser.id,
            sender_username: currentUser.username,
            content: message,
            timestamp: new Date().toISOString(),
            isSent: true
        });
        
        // Limpiar input
        input.value = '';
        
        // Detener notificación de escritura
        if (wsManager && wsManager.ws && wsManager.ws.readyState === WebSocket.OPEN) {
            wsManager.sendTypingNotification(currentRecipient.id, false);
        }
        
        DEBUG.success('=== MENSAJE ENVIADO COMPLETAMENTE ===');
        
    } catch (error) {
        DEBUG.error('Error enviando mensaje: ' + error.message);
        DEBUG.error('Stack: ' + error.stack);
        showToast('error', 'Error', 'No se pudo enviar el mensaje: ' + error.message);
    }
}

/**
 * Mostrar mensaje en el chat - Diseño estilo WhatsApp
 */
async function displayMessage(messageData) {
    const container = document.getElementById('messages');
    
    if (!container) {
        console.error('Contenedor de mensajes no encontrado');
        return;
    }
    
    const isSent = messageData.sender_id === currentUser.id;
    
    const messageDiv = document.createElement('div');
    messageDiv.className = `message-wrapper ${isSent ? 'sent' : 'received'}`;
    
    const time = new Date(messageData.timestamp).toLocaleTimeString('es-PE', {
        hour: '2-digit',
        minute: '2-digit'
    });
    
    let verificationIcon = '';
    if (messageData.signatureValid !== undefined) {
        verificationIcon = messageData.signatureValid 
            ? '<span class="verification-icon verified" title="Cifrado verificado">🔒✓</span>'
            : '<span class="verification-icon unverified" title="Advertencia de seguridad">⚠️</span>';
    }
    
    messageDiv.innerHTML = `
        <div class="message-bubble ${isSent ? 'sent' : 'received'}">
            <div class="message-text">${messageData.content}</div>
            <div class="message-footer">
                <span class="message-time">${time}</span>
                ${verificationIcon}
                ${isSent ? '<span class="message-status">✓✓</span>' : ''}
            </div>
        </div>
    `;
    
    container.appendChild(messageDiv);
    
    // Hacer scroll suave al final
    setTimeout(() => {
        container.scrollTo({
            top: container.scrollHeight,
            behavior: 'smooth'
        });
    }, 50);
}

/**
 * Manejar mensaje entrante
 */
function handleIncomingMessage(message) {
    // Solo mostrar si es del usuario seleccionado
    if (currentRecipient && message.sender_id === currentRecipient.id) {
        displayMessage(message);
    } else {
        // Mostrar notificación
        showToast('info', 'Nuevo mensaje', `${message.sender_username}: ${message.content.substring(0, 50)}...`);
    }
}

/**
 * Manejar notificación de escritura
 */
function handleTyping(e) {
    if (!currentRecipient || !wsManager) return;
    
    clearTimeout(typingTimeout);
    
    wsManager.sendTypingNotification(currentRecipient.id, true);
    
    typingTimeout = setTimeout(() => {
        if (wsManager) {
            wsManager.sendTypingNotification(currentRecipient.id, false);
        }
    }, 2000);
}

/**
 * Manejar notificación de escritura entrante
 */
function handleTypingNotification(data) {
    if (currentRecipient && data.user_id === currentRecipient.id) {
        const indicator = document.getElementById('typing-indicator');
        if (data.is_typing) {
            indicator.textContent = `${data.username} está escribiendo...`;
            indicator.style.display = 'block';
        } else {
            indicator.style.display = 'none';
        }
    }
}

/**
 * Actualizar estado de usuarios en línea
 */
function updateOnlineUsers(data) {
    if (data.users) {
        // Actualizar todos los usuarios
        data.users.forEach(userId => {
            updateUserStatus(userId, true);
        });
    }
}

/**
 * Actualizar estado de un usuario
 */
function updateUserStatus(userId, isOnline) {
    const userItem = document.querySelector(`[data-user-id="${userId}"]`);
    if (userItem) {
        const indicator = userItem.querySelector('.status-indicator');
        const text = userItem.querySelector('.status-text');
        
        if (isOnline) {
            indicator.classList.add('online');
            indicator.classList.remove('offline');
            text.textContent = 'En línea';
        } else {
            indicator.classList.remove('online');
            indicator.classList.add('offline');
            text.textContent = 'Desconectado';
        }
    }
}

/**
 * Mostrar modal de configuración
 */
function showSettingsModal() {
    const modal = document.getElementById('settings-modal');
    modal.classList.add('active');
    
    // Actualizar estado 2FA
    const status2FA = document.getElementById('2fa-status');
    status2FA.textContent = currentUser.totp_enabled ? 'Habilitado ✓' : 'Deshabilitado';
    status2FA.className = currentUser.totp_enabled ? 'status-enabled' : 'status-disabled';
}

/**
 * Configurar 2FA
 */
async function setup2FA() {
    try {
        const data = await API.setup2FA();
        
        // Mostrar QR code y secret
        alert(`Escanea este código QR con tu app de autenticación:\n\nSecret: ${data.secret}\n\nURL: ${data.qr_code_url}`);
        
        const code = prompt('Ingresa el código de 6 dígitos de tu app:');
        const password = prompt('Ingresa tu contraseña para confirmar:');
        
        if (code && password) {
            await API.enable2FA(code, password);
            showToast('success', '2FA habilitado', 'Autenticación de dos factores activada');
            currentUser.totp_enabled = true;
            showSettingsModal(); // Actualizar vista
        }
        
    } catch (error) {
        console.error('Error configurando 2FA:', error);
        showToast('error', 'Error', 'No se pudo configurar 2FA');
    }
}

/**
 * Rotar claves de cifrado
 */
async function rotateKeys() {
    if (!confirm('¿Estás seguro de querer rotar tus claves de cifrado? Esto generará un nuevo par de claves RSA.')) {
        return;
    }
    
    try {
        showToast('info', 'Rotando claves', 'Generando nuevas claves...');
        
        // Generar nuevas claves
        const newKeys = await CryptoModule.generateRSAKeyPair();
        
        // TODO: Enviar nuevas claves al servidor
        // await API.rotateKeys(newKeys.publicKey);
        
        // Guardar nueva clave privada
        localStorage.setItem(CONFIG.STORAGE_KEYS.PRIVATE_KEY, newKeys.privateKey);
        
        showToast('success', 'Claves rotadas', 'Tus claves han sido actualizadas');
        
    } catch (error) {
        console.error('Error rotando claves:', error);
        showToast('error', 'Error', 'No se pudo rotar las claves');
    }
}

/**
 * Mostrar información de cifrado
 */
function showEncryptionInfo() {
    const modal = document.getElementById('encryption-modal');
    modal.classList.add('active');
    
    // Actualizar información
    document.getElementById('encryption-status').innerHTML = `
        <p><strong>🔐 Cifrado activo:</strong> RSA-${CONFIG.RSA_KEY_SIZE} + AES-${CONFIG.AES_KEY_SIZE}</p>
        <p><strong>🔑 Par de claves:</strong> Generado</p>
        <p><strong>✍️ Firma digital:</strong> RSA-PSS con SHA-256</p>
        <p><strong>🛡️ Protección:</strong> End-to-End Encryption (E2EE)</p>
        <p><strong>📝 Audit Log:</strong> Habilitado</p>
    `;
}

/**
 * Cerrar modal
 */
function closeModal(modalId) {
    document.getElementById(modalId).classList.remove('active');
}

/**
 * Mostrar sidebar (para móviles)
 */
function showSidebar() {
    const sidebar = document.querySelector('.sidebar');
    const chatArea = document.querySelector('.chat-area');
    
    if (sidebar) sidebar.classList.remove('hide-mobile');
    if (chatArea) chatArea.classList.remove('show-mobile');
    
    // Ocultar el botón de volver
    const backBtn = document.querySelector('.btn-back-mobile');
    if (backBtn) backBtn.style.display = 'none';
}

/**
 * Cerrar sesión
 */
function handleLogout() {
    if (!confirm('¿Estás seguro de cerrar sesión?')) return;
    
    // Desconectar WebSocket
    wsManager.disconnect();
    
    // Limpiar almacenamiento
    localStorage.clear();
    
    // Resetear estado
    currentUser = null;
    currentRecipient = null;
    
    // Mostrar pantalla de login
    showAuthScreen();
    showLoginForm();
    
    showToast('info', 'Sesión cerrada', 'Has cerrado sesión correctamente');
}

/**
 * Mostrar notificación toast
 */
function showToast(type, title, message) {
    const container = document.getElementById('toast-container');
    
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    
    toast.innerHTML = `
        <strong>${title}</strong>
        <p>${message}</p>
    `;
    
    container.appendChild(toast);
    
    // Animación de entrada
    setTimeout(() => toast.classList.add('show'), 10);
    
    // Auto eliminar después de 4 segundos
    setTimeout(() => {
        toast.classList.remove('show');
        setTimeout(() => toast.remove(), 300);
    }, 4000);
}

// Iniciar aplicación cuando el DOM esté listo
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
} else {
    initApp();
}

// Exportar funciones globales
window.showToast = showToast;
window.updateUserStatus = updateUserStatus;
window.displayMessage = displayMessage;
