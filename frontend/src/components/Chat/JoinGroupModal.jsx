import React, { useState } from 'react';
import API from '../../services/api';
import CryptoModule from '../../utils/crypto';
import CONFIG from '../../utils/config';
import "../Common/Modal.css";

const JoinGroupModal = ({ isOpen, onClose, onGroupJoined, currentUser }) => {
    const [inviteCode, setInviteCode] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const handleJoinGroup = async () => {
        if (!inviteCode.trim()) {
            setError('Ingresa el código de invitación');
            return;
        }

        setLoading(true);
        setError('');

        try {
            // Nota: Para unirse con código, necesitamos que quien invita
            // nos proporcione la clave encriptada con nuestra clave pública.
            // Por ahora, implementaremos una solución donde el servidor
            // facilita esto o el admin debe enviarnos la clave.

            // Obtener mi clave privada para desencriptar
            const privateKeyPem = localStorage.getItem(CONFIG.STORAGE_KEYS.PRIVATE_KEY);
            if (!privateKeyPem) {
                throw new Error('No se encontró tu clave privada');
            }

            // OPCIÓN 1: Pedirle al admin que encripte la clave y la envíe junto con el código
            // Por simplicidad, asumiremos que necesitamos la clave AES encriptada del grupo

            // TODO: Implementar flujo donde el admin envía la clave encriptada
            // Por ahora, usaremos un placeholder
            const encryptedGroupKey = 'placeholder'; // Esto debe venir del admin

            const joinedGroup = await API.joinGroupWithCode(inviteCode, encryptedGroupKey);

            console.log('✅ Te uniste al grupo:', joinedGroup);

            onGroupJoined(joinedGroup);
            onClose();
            setInviteCode('');
        } catch (error) {
            console.error('Error uniéndose al grupo:', error);
            setError(error.response?.data?.detail || 'Código inválido o expirado');
        } finally {
            setLoading(false);
        }
    };

    if (!isOpen) return null;

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h2>🔑 Unirse a Grupo</h2>
                    <button className="modal-close" onClick={onClose}>×</button>
                </div>

                {error && (
                    <div className="alert alert-error">
                        {error}
                    </div>
                )}

                <div className="modal-body">
                    <div className="form-group">
                        <label htmlFor="inviteCode">Código de Invitación</label>
                        <input
                            id="inviteCode"
                            type="text"
                            className="form-control"
                            placeholder="Ingresa el código del grupo..."
                            value={inviteCode}
                            onChange={(e) => setInviteCode(e.target.value)}
                            disabled={loading}
                            autoFocus
                        />
                        <p style={{ fontSize: '0.85rem', color: '#666', marginTop: '8px' }}>
                            Solicita el código al administrador del grupo
                        </p>
                    </div>

                    <div className="alert alert-info">
                        <strong>ℹ️ Nota:</strong> Para unirte al grupo necesitas que el administrador
                        te agregue directamente o te proporcione el código de invitación.
                        El flujo actual requiere que el admin te agregue usando tu ID de usuario.
                    </div>
                </div>

                <div className="modal-footer">
                    <button
                        className="btn btn-secondary"
                        onClick={onClose}
                        disabled={loading}
                    >
                        Cancelar
                    </button>
                    <button
                        className="btn btn-primary"
                        onClick={handleJoinGroup}
                        disabled={!inviteCode.trim() || loading}
                    >
                        {loading ? 'Uniéndose...' : 'Unirse al Grupo'}
                    </button>
                </div>
            </div>
        </div>
    );
};

export default JoinGroupModal;
