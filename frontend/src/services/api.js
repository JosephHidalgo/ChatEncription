import axios from 'axios';
import CONFIG from '../utils/config';

// Configurar axios
const api = axios.create({
    baseURL: CONFIG.API_URL,
    headers: {
        'Content-Type': 'application/json'
    }
});

// Interceptor para agregar token a las peticiones
api.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem(CONFIG.STORAGE_KEYS.ACCESS_TOKEN);
        if (token && !config.skipAuth) {
            config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
    },
    (error) => {
        return Promise.reject(error);
    }
);

// Interceptor para manejar errores
api.interceptors.response.use(
    (response) => response,
    (error) => {
        if (error.response?.status === 401) {
            // Token inválido o expirado
            localStorage.clear();
            window.location.href = '/';
        }
        return Promise.reject(error);
    }
);

const API = {
    /**
     * Registrar nuevo usuario
     */
    async register(username, email, password, publicKey, encryptedPrivateKey = null) {
        const payload = {
            username,
            email,
            password,
            public_key: publicKey
        };
        
        // Solo incluir encrypted_private_key si se proporciona
        if (encryptedPrivateKey) {
            payload.encrypted_private_key = encryptedPrivateKey;
        }
        
        const response = await api.post('/auth/register', payload, { skipAuth: true });
        return response.data;
    },

    /**
     * Iniciar sesión
     */
    async login(username, password, totp_code = null) {
        const response = await api.post('/auth/login', {
            username,
            password,
            totp_code
        }, { skipAuth: true });
        return response.data;
    },

    /**
     * Obtener información del usuario actual
     */
    async getCurrentUser() {
        const response = await api.get('/auth/me');
        return response.data;
    },

    /**
     * Listar todos los usuarios
     */
    async getUsers() {
        const response = await api.get('/auth/users');
        return response.data;
    },

    /**
     * Obtener clave pública de un usuario
     */
    async getUserPublicKey(userId) {
        const response = await api.get(`/auth/users/public-key/${userId}`);
        return response.data;
    },

    /**
     * Obtener MI clave privada RSA
     */
    async getMyPrivateKey() {
        const response = await api.get('/auth/me/private-key');
        return response.data;
    },

    /**
     * Configurar 2FA
     */
    async setup2FA() {
        const response = await api.post('/auth/2fa/setup');
        return response.data;
    },

    /**
     * Habilitar 2FA
     */
    async enable2FA(totp_code) {
        const response = await api.post('/auth/2fa/enable', { totp_code });
        return response.data;
    },

    /**
     * Deshabilitar 2FA
     */
    async disable2FA(totp_code) {
        const response = await api.post('/auth/2fa/disable', { totp_code });
        return response.data;
    },

    /**
     * Rotar claves RSA
     */
    async rotateKeys(new_public_key) {
        const response = await api.post('/auth/rotate-keys', { new_public_key });
        return response.data;
    },

    /**
     * Obtener mensajes con un usuario
     */
    async getMessages(userId, limit = 50) {
        const response = await api.get(`/api/messages/history/${userId}?limit=${limit}`);
        return response.data.messages;
    },

    /**
     * Enviar mensaje
     */
    async sendMessage(messageData) {
        const response = await api.post('/api/messages/send', messageData);
        return response.data;
    },

    /**
     * Marcar mensaje como leído
     */
    async markAsRead(messageId) {
        const response = await api.post(`/api/messages/${messageId}/read`);
        return response.data;
    },

    // ==================== GRUPOS ====================

    /**
     * Crear grupo
     */
    async createGroup(groupData) {
        const response = await api.post('/groups/', groupData);
        return response.data;
    },

    /**
     * Obtener mis grupos
     */
    async getMyGroups() {
        const response = await api.get('/groups/');
        return response.data;
    },

    /**
     * Obtener detalles de un grupo
     */
    async getGroup(groupId) {
        const response = await api.get(`/groups/${groupId}`);
        return response.data;
    },

    /**
     * Obtener miembros de un grupo
     */
    async getGroupMembers(groupId) {
        const response = await api.get(`/groups/${groupId}/members`);
        return response.data;
    },

    /**
     * Agregar miembro a grupo (solo admin)
     */
    async addMemberToGroup(groupId, userId, encryptedGroupKey) {
        const response = await api.post(`/groups/${groupId}/members`, {
            user_id: userId,
            encrypted_group_key: encryptedGroupKey
        });
        return response.data;
    },

    /**
     * Generar código de invitación (solo admin)
     */
    async generateInviteCode(groupId, maxUses = null, expiresInHours = null) {
        const response = await api.post(`/groups/${groupId}/invite-codes`, {
            max_uses: maxUses,
            expires_in_hours: expiresInHours
        });
        return response.data;
    },

    /**
     * Unirse a grupo con código
     */
    async joinGroupWithCode(code, encryptedGroupKey) {
        const response = await api.post('/groups/join', {
            code: code,
            encrypted_group_key: encryptedGroupKey
        });
        return response.data;
    },

    /**
     * Obtener mi clave de grupo encriptada
     */
    async getMyEncryptedGroupKey(groupId) {
        const response = await api.get(`/groups/${groupId}/encrypted-key`);
        return response.data;
    },

    /**
     * Enviar mensaje a grupo
     */
    async sendGroupMessage(groupId, messageData) {
        const response = await api.post(`/groups/${groupId}/messages`, {
            group_id: groupId,
            ...messageData
        });
        return response.data;
    },

    /**
     * Obtener mensajes de grupo
     */
    async getGroupMessages(groupId, limit = 50, beforeId = null) {
        let url = `/groups/${groupId}/messages?limit=${limit}`;
        if (beforeId) {
            url += `&before_id=${beforeId}`;
        }
        const response = await api.get(url);
        return response.data;
    }
};

export default API;
