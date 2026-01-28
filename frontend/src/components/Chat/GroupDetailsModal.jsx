import React, { useState, useEffect } from 'react';
import API from '../../services/api';
import CryptoModule from '../../utils/crypto';
import CONFIG from '../../utils/config';
import "../Common/Modal.css";

const GroupDetailsModal = ({ isOpen, onClose, group, currentUser, onRefresh }) => {
    const [members, setMembers] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [showAddMember, setShowAddMember] = useState(false);
    const [showInviteCode, setShowInviteCode] = useState(false);
    const [availableUsers, setAvailableUsers] = useState([]);
    const [selectedUser, setSelectedUser] = useState('');
    const [inviteCode, setInviteCode] = useState(null);
    const [addingMember, setAddingMember] = useState(false);
    const [generatingCode, setGeneratingCode] = useState(false);

    const isAdmin = group && currentUser && group.admin_id === currentUser.id;

    useEffect(() => {
        if (isOpen && group) {
            loadMembers();
            loadAvailableUsers();
        }
    }, [isOpen, group]);

    const loadMembers = async () => {
        if (!group) return;
        
        setLoading(true);
        try {
            const membersData = await API.getGroupMembers(group.id);
            setMembers(membersData);
        } catch (error) {
            console.error('Error cargando miembros:', error);
            setError('Error al cargar miembros');
        } finally {
            setLoading(false);
        }
    };

    const loadAvailableUsers = async () => {
        try {
            const users = await API.getUsers();
            setAvailableUsers(users);
        } catch (error) {
            console.error('Error cargando usuarios:', error);
        }
    };

    const handleAddMember = async () => {
        if (!selectedUser) {
            setError('Selecciona un usuario');
            return;
        }

        // Verificar si ya es miembro
        if (members.some(m => m.user_id === parseInt(selectedUser))) {
            setError('Este usuario ya es miembro del grupo');
            return;
        }

        setAddingMember(true);
        setError('');

        try {
            // 1. Obtener clave del grupo del localStorage
            const groupKeyHex = localStorage.getItem(
                `${CONFIG.STORAGE_KEYS.GROUP_KEY_PREFIX}${group.id}`
            );

            if (!groupKeyHex) {
                throw new Error('No se encontró la clave del grupo. Recárgala desde el servidor.');
            }

            // 2. Obtener clave pública del nuevo miembro
            const publicKeyData = await API.getUserPublicKey(parseInt(selectedUser));
            const publicKeyPem = publicKeyData.public_key_rsa;

            // 3. Encriptar clave del grupo con RSA del nuevo miembro
            const encryptedKey = await CryptoModule.encryptGroupKeyForMember(
                groupKeyHex,
                publicKeyPem
            );

            // 4. Agregar miembro al grupo
            await API.addMemberToGroup(group.id, parseInt(selectedUser), encryptedKey);

            // 5. Recargar miembros
            await loadMembers();
            setShowAddMember(false);
            setSelectedUser('');
            onRefresh && onRefresh();
        } catch (error) {
            console.error('Error agregando miembro:', error);
            setError(error.response?.data?.detail || 'Error al agregar miembro');
        } finally {
            setAddingMember(false);
        }
    };

    const handleGenerateInviteCode = async () => {
        setGeneratingCode(true);
        setError('');

        try {
            const codeData = await API.generateInviteCode(group.id, 10, 24);
            setInviteCode(codeData);
        } catch (error) {
            console.error('Error generando código:', error);
            setError(error.response?.data?.detail || 'Error al generar código');
        } finally {
            setGeneratingCode(false);
        }
    };

    const copyInviteCode = () => {
        if (inviteCode) {
            navigator.clipboard.writeText(inviteCode.code);
            alert('Código copiado al portapapeles');
        }
    };

    if (!isOpen || !group) return null;

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content modal-large" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <div>
                        <h2>👥 {group.name}</h2>
                        {group.description && (
                            <p style={{ margin: '5px 0 0 0', color: '#666', fontSize: '0.9rem' }}>
                                {group.description}
                            </p>
                        )}
                    </div>
                    <button className="modal-close" onClick={onClose}>×</button>
                </div>

                {error && (
                    <div className="alert alert-error">
                        {error}
                    </div>
                )}

                <div className="modal-body">
                    <div className="group-details-section">
                        <h3>Miembros ({members.length})</h3>
                        
                        {loading ? (
                            <p>Cargando miembros...</p>
                        ) : (
                            <div className="members-list">
                                {members.map(member => (
                                    <div key={member.id} className="member-item">
                                        <div className="member-info">
                                            <div className="member-avatar">
                                                {member.username.charAt(0).toUpperCase()}
                                            </div>
                                            <div className="member-details">
                                                <div className="member-name">
                                                    {member.username}
                                                    {member.is_admin && (
                                                        <span className="badge badge-admin">Admin</span>
                                                    )}
                                                </div>
                                                <div className="member-joined">
                                                    Unido: {new Date(member.joined_at).toLocaleDateString()}
                                                </div>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        )}

                        {isAdmin && (
                            <div style={{ marginTop: '20px' }}>
                                <button
                                    className="btn btn-primary"
                                    onClick={() => setShowAddMember(!showAddMember)}
                                >
                                    {showAddMember ? 'Cancelar' : '+ Agregar Miembro'}
                                </button>

                                {showAddMember && (
                                    <div className="add-member-form">
                                        <select
                                            className="form-control"
                                            value={selectedUser}
                                            onChange={(e) => setSelectedUser(e.target.value)}
                                            disabled={addingMember}
                                        >
                                            <option value="">Seleccionar usuario...</option>
                                            {availableUsers
                                                .filter(u => !members.some(m => m.user_id === u.id))
                                                .map(user => (
                                                    <option key={user.id} value={user.id}>
                                                        {user.username} ({user.email})
                                                    </option>
                                                ))}
                                        </select>
                                        <button
                                            className="btn btn-success"
                                            onClick={handleAddMember}
                                            disabled={!selectedUser || addingMember}
                                        >
                                            {addingMember ? 'Agregando...' : 'Agregar'}
                                        </button>
                                    </div>
                                )}
                            </div>
                        )}
                    </div>

                    {isAdmin && (
                        <div className="group-details-section">
                            <h3>Código de Invitación</h3>
                            <p style={{ fontSize: '0.9rem', color: '#666' }}>
                                Genera un código para que otros usuarios puedan unirse al grupo
                            </p>

                            {!inviteCode ? (
                                <button
                                    className="btn btn-primary"
                                    onClick={handleGenerateInviteCode}
                                    disabled={generatingCode}
                                >
                                    {generatingCode ? 'Generando...' : '🔑 Generar Código'}
                                </button>
                            ) : (
                                <div className="invite-code-display">
                                    <div className="code-box">
                                        <code>{inviteCode.code}</code>
                                        <button
                                            className="btn btn-sm"
                                            onClick={copyInviteCode}
                                            title="Copiar código"
                                        >
                                            📋
                                        </button>
                                    </div>
                                    <div className="code-info">
                                        <p>• Usos: {inviteCode.current_uses} / {inviteCode.max_uses || '∞'}</p>
                                        {inviteCode.expires_at && (
                                            <p>• Expira: {new Date(inviteCode.expires_at).toLocaleString()}</p>
                                        )}
                                    </div>
                                    <button
                                        className="btn btn-secondary btn-sm"
                                        onClick={() => setInviteCode(null)}
                                    >
                                        Generar Nuevo
                                    </button>
                                </div>
                            )}
                        </div>
                    )}
                </div>

                <div className="modal-footer">
                    <button className="btn btn-secondary" onClick={onClose}>
                        Cerrar
                    </button>
                </div>
            </div>
        </div>
    );
};

export default GroupDetailsModal;
