import { createContext, useContext, useState, useEffect } from 'react';
import API from '../services/api';
import wsService from '../services/websocket';
import CryptoModule from '../utils/crypto';
import CONFIG from '../utils/config';

const AuthContext = createContext(null);

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const [privateKey, setPrivateKey] = useState(null);

    useEffect(() => {
        const checkSession = async () => {
            const token = localStorage.getItem(CONFIG.STORAGE_KEYS.ACCESS_TOKEN);
            
            if (token) {
                try {
                    const userData = await API.getCurrentUser();
                    setUser(userData);
                    
                    // Cargar clave privada del almacenamiento local
                    const storedPrivateKey = localStorage.getItem(CONFIG.STORAGE_KEYS.PRIVATE_KEY);
                    if (storedPrivateKey) {
                        setPrivateKey(storedPrivateKey);
                    }
                    
                    // Conectar WebSocket
                    wsService.connect(token);
                } catch (error) {
                    console.error('Error verificando sesión:', error);
                    logout();
                }
            }
            
            setLoading(false);
        };

        checkSession();
    }, []);

    const register = async (username, email, password) => {
        try {
            // Generar par de claves RSA
            const keyPair = await CryptoModule.generateRSAKeyPair();
            
            // Cifrar la clave privada con la contraseña del usuario
            const encryptedPrivateKey = await CryptoModule.encryptPrivateKeyWithPassword(
                keyPair.privateKey,
                password
            );
            
            // Guardar clave privada SIN CIFRAR localmente
            localStorage.setItem(CONFIG.STORAGE_KEYS.PRIVATE_KEY, keyPair.privateKey);
            localStorage.setItem(CONFIG.STORAGE_KEYS.PUBLIC_KEY, keyPair.publicKey);
            setPrivateKey(keyPair.privateKey);
            
            console.log('✓ Claves RSA generadas y guardadas localmente');
            
            // Registrar usuario con clave pública Y clave privada cifrada (backup)
            await API.register(username, email, password, keyPair.publicKey, encryptedPrivateKey);
            
            console.log('✓ Usuario registrado exitosamente');
            
            // Hacer login automático
            console.log('Haciendo login automático...');
            const loginResult = await login(username, password);
            
            if (loginResult.success) {
                console.log('✓ Login automático exitoso');
            } else {
                console.error('✗ Error en login automático:', loginResult.error);
            }
            
            return loginResult;
        } catch (error) {
            console.error('Error en registro:', error);
            // Limpiar claves si el registro falla
            localStorage.removeItem(CONFIG.STORAGE_KEYS.PRIVATE_KEY);
            localStorage.removeItem(CONFIG.STORAGE_KEYS.PUBLIC_KEY);
            setPrivateKey(null);
            
            return { 
                success: false, 
                error: error.response?.data?.detail || error.message 
            };
        }
    };

    const login = async (username, password, totpCode = null) => {
        try {
            const response = await API.login(username, password, totpCode);
            
            // Guardar tokens
            localStorage.setItem(CONFIG.STORAGE_KEYS.ACCESS_TOKEN, response.access_token);
            if (response.refresh_token) {
                localStorage.setItem(CONFIG.STORAGE_KEYS.REFRESH_TOKEN, response.refresh_token);
            }
            
            // Cargar usuario
            const userData = await API.getCurrentUser();
            localStorage.setItem(CONFIG.STORAGE_KEYS.USER_ID, userData.id.toString());
            localStorage.setItem(CONFIG.STORAGE_KEYS.USER_DATA, JSON.stringify(userData));
            setUser(userData);
            
            // Intentar cargar clave privada del localStorage primero
            let privateKey = localStorage.getItem(CONFIG.STORAGE_KEYS.PRIVATE_KEY);
            
            // Si no está en localStorage, intentar obtenerla del servidor
            if (!privateKey || privateKey === 'undefined' || privateKey === 'null') {
                console.log('Clave privada no encontrada localmente, intentando obtener del servidor...');
                try {
                    const privateKeyData = await API.getMyPrivateKey();
                    const serverPrivateKey = privateKeyData?.private_key_rsa || privateKeyData?.private_key;
                    
                    if (serverPrivateKey && serverPrivateKey !== 'undefined') {
                        // Verificar si es una clave legacy (formato PEM sin cifrar)
                        if (serverPrivateKey.includes('-----BEGIN')) {
                            // Clave legacy sin cifrar
                            privateKey = serverPrivateKey;
                            localStorage.setItem(CONFIG.STORAGE_KEYS.PRIVATE_KEY, privateKey);
                            console.log('✓ Clave privada legacy recuperada del servidor');
                        } else {
                            // Clave cifrada con contraseña, intentar descifrar
                            try {
                                privateKey = await CryptoModule.decryptPrivateKeyWithPassword(
                                    serverPrivateKey,
                                    password
                                );
                                // Guardar en localStorage para uso futuro
                                localStorage.setItem(CONFIG.STORAGE_KEYS.PRIVATE_KEY, privateKey);
                                console.log('✓ Clave privada recuperada y descifrada del servidor');
                            } catch (decryptError) {
                                console.error('Error al descifrar clave privada:', decryptError);
                                console.error('⚠️ No se pudo descifrar la clave privada');
                            }
                        }
                    }
                } catch (error) {
                    console.warn('No se pudo obtener clave privada del servidor:', error);
                }
            } else {
                console.log('✓ Clave privada cargada desde localStorage');
            }
            
            if (privateKey && privateKey !== 'undefined') {
                setPrivateKey(privateKey);
            } else {
                console.error('⚠️ No hay clave privada disponible. Los mensajes no podrán descifrarse.');
            }
            
            // Conectar WebSocket
            wsService.connect(response.access_token);
            
            return { success: true };
        } catch (error) {
            console.error('Error en login:', error);
            
            // Verificar si requiere 2FA
            if (error.response?.status === 403 && error.response?.data?.detail?.includes('2FA')) {
                return { 
                    success: false, 
                    requires2FA: true,
                    error: error.response.data.detail 
                };
            }
            
            return { 
                success: false, 
                error: error.response?.data?.detail || error.message 
            };
        }
    };

    const logout = () => {
        // Desconectar WebSocket
        wsService.disconnect();
        
        // Limpiar almacenamiento
        localStorage.clear();
        
        // Limpiar estado
        setUser(null);
        setPrivateKey(null);
    };

    const setup2FA = async () => {
        try {
            const response = await API.setup2FA();
            return { success: true, data: response };
        } catch (error) {
            console.error('Error configurando 2FA:', error);
            return { 
                success: false, 
                error: error.response?.data?.detail || error.message 
            };
        }
    };

    const enable2FA = async (totpCode) => {
        try {
            await API.enable2FA(totpCode);
            
            // Actualizar usuario
            const userData = await API.getCurrentUser();
            setUser(userData);
            
            return { success: true };
        } catch (error) {
            console.error('Error habilitando 2FA:', error);
            return { 
                success: false, 
                error: error.response?.data?.detail || error.message 
            };
        }
    };

    const rotateKeys = async () => {
        try {
            // Generar nuevo par de claves
            const keyPair = await CryptoModule.generateRSAKeyPair();
            
            // Actualizar en el servidor
            await API.rotateKeys(keyPair.publicKey);
            
            // Guardar localmente
            localStorage.setItem(CONFIG.STORAGE_KEYS.PRIVATE_KEY, keyPair.privateKey);
            localStorage.setItem(CONFIG.STORAGE_KEYS.PUBLIC_KEY, keyPair.publicKey);
            setPrivateKey(keyPair.privateKey);
            
            return { success: true };
        } catch (error) {
            console.error('Error rotando claves:', error);
            return { 
                success: false, 
                error: error.response?.data?.detail || error.message 
            };
        }
    };

    const value = {
        user,
        privateKey,
        loading,
        register,
        login,
        logout,
        setup2FA,
        enable2FA,
        rotateKeys
    };

    return (
        <AuthContext.Provider value={value}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => {
    const context = useContext(AuthContext);
    if (!context) {
        throw new Error('useAuth debe usarse dentro de AuthProvider');
    }
    return context;
};

export default AuthContext;
