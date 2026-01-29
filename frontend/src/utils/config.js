const isSecure = window.location.protocol === 'https:';
const protocol = isSecure ? 'https' : 'http';
const wsProtocol = isSecure ? 'wss' : 'ws';

const CONFIG = {
    API_URL: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? `${protocol}://localhost:8000`
        : `${protocol}://${window.location.hostname}:8000`,

    WS_URL: window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
        ? `${wsProtocol}://localhost:8000/ws/chat`
        : `${wsProtocol}://${window.location.hostname}:8000/ws/chat`,

    APP_NAME: 'SecureChat',
    VERSION: '2.0.0',

    RSA_KEY_SIZE: 2048,
    AES_KEY_SIZE: 256,

    // Timeouts
    TYPING_TIMEOUT: 1000,
    MESSAGE_RETRY: 3,

    // Almacenamiento local
    STORAGE_KEYS: {
        ACCESS_TOKEN: 'access_token',
        REFRESH_TOKEN: 'refresh_token',
        USER_DATA: 'user_data',
        USER_ID: 'user_id',
        PRIVATE_KEY: 'private_key',
        PUBLIC_KEY: 'public_key',
        GROUP_KEY_PREFIX: 'group_key_'  // Prefijo para claves de grupo: group_key_<group_id>
    }
};

export default CONFIG;
