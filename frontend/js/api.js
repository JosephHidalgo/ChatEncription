// Módulo de API para comunicación con el backend
const API = {
    /**
     * Realiza una petición HTTP al backend
     */
    async request(endpoint, options = {}) {
        const url = `${CONFIG.API_URL}${endpoint}`;
        const token = localStorage.getItem(CONFIG.STORAGE_KEYS.ACCESS_TOKEN);
        
        const defaultHeaders = {
            'Content-Type': 'application/json'
        };
        
        if (token && !options.skipAuth) {
            defaultHeaders['Authorization'] = `Bearer ${token}`;
        }
        
        const config = {
            ...options,
            headers: {
                ...defaultHeaders,
                ...options.headers
            }
        };
        
        if (options.body && typeof options.body === 'object') {
            config.body = JSON.stringify(options.body);
        }
        
        try {
            const response = await fetch(url, config);
            
            // Manejar errores HTTP
            if (!response.ok) {
                const error = await response.json();
                throw new Error(error.detail || 'Error en la petición');
            }
            
            return await response.json();
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    },

    /**
     * Registrar nuevo usuario
     */
    async register(username, email, password) {
        return this.request('/auth/register', {
            method: 'POST',
            body: { username, email, password },
            skipAuth: true
        });
    },

    /**
     * Iniciar sesión
     */
    async login(username, password, totp_code = null) {
        return this.request('/auth/login', {
            method: 'POST',
            body: { username, password, totp_code },
            skipAuth: true
        });
    },

    /**
     * Obtener información del usuario actual
     */
    async getCurrentUser() {
        return this.request('/auth/me');
    },

    /**
     * Listar todos los usuarios
     */
    async getUsers() {
        return this.request('/auth/users');
    },

    /**
     * Obtener clave pública de un usuario
     */
    async getUserPublicKey(userId) {
        return this.request(`/auth/users/public-key/${userId}`);
    },

    /**
     * Configurar 2FA
     */
    async setup2FA() {
        return this.request('/auth/totp/setup', { method: 'POST' });
    },

    /**
     * Habilitar 2FA
     */
    async enable2FA(totp_code, password) {
        return this.request('/auth/totp/enable', {
            method: 'POST',
            body: { totp_code, password }
        });
    },

    /**
     * Obtener historial de mensajes con un usuario
     */
    async getMessageHistory(recipientId, limit = 50) {
        return this.request(`/auth/messages/history/${recipientId}?limit=${limit}`);
    },

    /**
     * Health check del servidor
     */
    async healthCheck() {
        return this.request('/health', { skipAuth: true });
    }
};

// Exportar para uso global
window.API = API;
