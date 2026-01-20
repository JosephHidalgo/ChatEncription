import { useState } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import './Modal.css';

const SettingsModal = ({ onClose }) => {
    const { user, setup2FA, enable2FA, rotateKeys } = useAuth();
    const [loading, setLoading] = useState(false);
    const [qrCode, setQrCode] = useState(null);
    const [totpCode, setTotpCode] = useState('');
    const [message, setMessage] = useState('');

    const handleSetup2FA = async () => {
        setLoading(true);
        setMessage('');

        const result = await setup2FA();

        if (result.success) {
            setQrCode(result.data.qr_code);
            setMessage('Escanea el código QR con tu app de autenticación');
        } else {
            setMessage('Error: ' + result.error);
        }

        setLoading(false);
    };

    const handleEnable2FA = async () => {
        if (!totpCode || totpCode.length !== 6) {
            setMessage('Por favor ingresa el código de 6 dígitos');
            return;
        }

        setLoading(true);
        setMessage('');

        const result = await enable2FA(totpCode);

        if (result.success) {
            setMessage('✅ 2FA habilitado correctamente');
            setQrCode(null);
            setTotpCode('');
        } else {
            setMessage('Error: ' + result.error);
        }

        setLoading(false);
    };

    const handleRotateKeys = async () => {
        if (!confirm('¿Estás seguro de que quieres rotar tus claves? Esto generará un nuevo par de claves RSA.')) {
            return;
        }

        setLoading(true);
        setMessage('');

        const result = await rotateKeys();

        if (result.success) {
            setMessage('✅ Claves rotadas correctamente');
        } else {
            setMessage('Error: ' + result.error);
        }

        setLoading(false);
    };

    return (
        <div className="modal" onClick={onClose}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h2><i className="fas fa-cog"></i> Configuración</h2>
                    <button className="modal-close" onClick={onClose}>
                        &times;
                    </button>
                </div>

                <div className="modal-body">
                    {message && (
                        <div className={`message ${message.includes('Error') ? 'error' : 'success'}`}>
                            {message}
                        </div>
                    )}

                    <div className="setting-item">
                        <h3><i className="fas fa-shield-alt"></i> Autenticación de Dos Factores (2FA)</h3>
                        <p>
                            Estado: <strong>{user?.totp_enabled ? 'Habilitado ✅' : 'Deshabilitado ❌'}</strong>
                        </p>

                        {!user?.totp_enabled && !qrCode && (
                            <button
                                className="btn btn-primary"
                                onClick={handleSetup2FA}
                                disabled={loading}
                            >
                                <i className="fas fa-key"></i>
                                {loading ? ' Configurando...' : ' Configurar 2FA'}
                            </button>
                        )}

                        {qrCode && (
                            <div className="qr-code-section">
                                <img src={qrCode} alt="QR Code 2FA" />
                                <div className="form-group">
                                    <label>Ingresa el código de verificación:</label>
                                    <input
                                        type="text"
                                        value={totpCode}
                                        onChange={(e) => setTotpCode(e.target.value)}
                                        placeholder="123456"
                                        maxLength="6"
                                        disabled={loading}
                                    />
                                </div>
                                <button
                                    className="btn btn-primary"
                                    onClick={handleEnable2FA}
                                    disabled={loading}
                                >
                                    <i className="fas fa-check"></i>
                                    {loading ? ' Verificando...' : ' Habilitar 2FA'}
                                </button>
                            </div>
                        )}
                    </div>

                    <div className="setting-item">
                        <h3><i className="fas fa-sync-alt"></i> Rotación de Claves</h3>
                        <p>Genera un nuevo par de claves RSA</p>
                        <button
                            className="btn btn-secondary"
                            onClick={handleRotateKeys}
                            disabled={loading}
                        >
                            <i className="fas fa-redo"></i>
                            {loading ? ' Rotando...' : ' Rotar Claves'}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default SettingsModal;
