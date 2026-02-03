import React, { useState, useEffect } from 'react';
import API from '../../services/api';
import CryptoModule from '../../utils/crypto';
import CONFIG from '../../utils/config';
import "../Common/Modal.css";

const CreateGroupModal = ({ isOpen, onClose, onGroupCreated, currentUser }) => {
    const [groupName, setGroupName] = useState('');
    const [groupDescription, setGroupDescription] = useState('');
    const [availableUsers, setAvailableUsers] = useState([]);
    const [selectedMembers, setSelectedMembers] = useState([]);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');
    const [step, setStep] = useState(1); // 1: Info, 2: Miembros

    useEffect(() => {
        if (isOpen) {
            loadUsers();
            setGroupName('');
            setGroupDescription('');
            setSelectedMembers([]);
            setError('');
            setStep(1);
        }
    }, [isOpen]);

    const loadUsers = async () => {
        try {
            const users = await API.getUsers();
            // Filtrar el usuario actual
            setAvailableUsers(users.filter(u => u.id !== currentUser.id));
        } catch (error) {
            // console.error('Error cargando usuarios:', error);
            setError('Error cargando usuarios');
        }
    };

    const toggleMember = (userId) => {
        setSelectedMembers(prev => {
            if (prev.includes(userId)) {
                return prev.filter(id => id !== userId);
            } else {
                return [...prev, userId];
            }
        });
    };

    const handleCreateGroup = async () => {
        if (!groupName.trim()) {
            setError('El nombre del grupo es requerido');
            return;
        }

        if (selectedMembers.length === 0) {
            setError('Debes seleccionar al menos un miembro');
            return;
        }

        setLoading(true);
        setError('');

        try {
            // 1. Generar clave AES para el grupo
            const groupKey = await CryptoModule.generateGroupKey();
            // console.log('Clave de grupo generada:', groupKey.keyHex.substring(0, 32) + '...');

            // 2. Calcular hash SHA-256 de la clave
            const groupKeyHash = await CryptoModule.hashSHA256(groupKey.keyHex);

            // 3. Obtener claves públicas de todos los miembros (incluyendo admin)
            const memberIds = [currentUser.id, ...selectedMembers];
            const encryptedKeys = {};

            for (const memberId of memberIds) {
                try {
                    // Obtener clave pública del miembro
                    const publicKeyData = await API.getUserPublicKey(memberId);
                    const publicKeyPem = publicKeyData.public_key_rsa;

                    // Encriptar clave del grupo con RSA del miembro
                    const encryptedKey = await CryptoModule.encryptGroupKeyForMember(
                        groupKey.keyHex,
                        publicKeyPem
                    );

                    encryptedKeys[memberId] = encryptedKey;
                    // console.log(`Clave encriptada para miembro ${memberId}`);
                } catch (error) {
                    // console.error(`Error encriptando clave para miembro ${memberId}:`, error);
                    throw new Error(`Error procesando miembro ${memberId}`);
                }
            }

            // 4. Crear el grupo en el servidor
            const groupData = {
                name: groupName,
                description: groupDescription || null,
                member_ids: selectedMembers,
                encrypted_keys: encryptedKeys,
                group_key_hash: groupKeyHash
            };

            const newGroup = await API.createGroup(groupData);

            // 5. Guardar clave AES del grupo en localStorage
            const storageKey = `${CONFIG.STORAGE_KEYS.GROUP_KEY_PREFIX}${newGroup.id}`;
            localStorage.setItem(storageKey, groupKey.keyHex);

            // console.log('✅ Grupo creado exitosamente:', newGroup);
            // console.log('🔑 Clave guardada en localStorage con key:', storageKey);
            // console.log('🔑 Verificando clave guardada:', localStorage.getItem(storageKey)?.substring(0, 32) + '...');

            onGroupCreated(newGroup);
            onClose();
        } catch (error) {
            // console.error('Error creando grupo:', error);
            setError(error.response?.data?.detail || 'Error al crear el grupo');
        } finally {
            setLoading(false);
        }
    };

    if (!isOpen) return null;

    return (
        <div className="modal-overlay" onClick={onClose}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h2>Crear Grupo Seguro</h2>
                    <button className="modal-close" onClick={onClose}>×</button>
                </div>

                {error && (
                    <div className="alert alert-error">
                        {error}
                    </div>
                )}

                <div className="modal-body">
                    {step === 1 ? (
                        <div className="form-group">
                            <label htmlFor="groupName">Nombre del Grupo *</label>
                            <input
                                id="groupName"
                                type="text"
                                className="form-control"
                                placeholder="Ej: Proyecto Final"
                                value={groupName}
                                onChange={(e) => setGroupName(e.target.value)}
                                maxLength={100}
                                disabled={loading}
                            />

                            <label htmlFor="groupDescription" style={{ marginTop: '15px' }}>
                                Descripción (Opcional)
                            </label>
                            <input
                                id="groupDescription"
                                type="text"
                                className="form-control"
                                placeholder="Descripción del grupo..."
                                value={groupDescription}
                                onChange={(e) => setGroupDescription(e.target.value)}
                                maxLength={500}
                                disabled={loading}
                            />

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
                                    onClick={() => setStep(2)}
                                    disabled={!groupName.trim() || loading}
                                >
                                    Siguiente →
                                </button>
                            </div>
                        </div>
                    ) : (
                        <div className="form-group">
                            <label>Seleccionar Miembros *</label>
                            <p style={{ fontSize: '0.9rem', color: '#666' }}>
                                Selecciona los usuarios que formarán parte del grupo
                            </p>

                            <div className="members-list">
                                {availableUsers.map(user => (
                                    <div
                                        key={user.id}
                                        className={`member-item ${selectedMembers.includes(user.id) ? 'selected' : ''}`}
                                        onClick={() => toggleMember(user.id)}
                                    >
                                        <div className="member-info">
                                            <div className="member-avatar">
                                                {user.username.charAt(0).toUpperCase()}
                                            </div>
                                            <div className="member-details">
                                                <div className="member-name">{user.username}</div>
                                                <div className="member-email">{user.email}</div>
                                            </div>
                                        </div>
                                        <div className="member-checkbox">
                                            {selectedMembers.includes(user.id) && '✓'}
                                        </div>
                                    </div>
                                ))}
                            </div>

                            <div className="selected-count">
                                {selectedMembers.length} miembro{selectedMembers.length !== 1 ? 's' : ''} seleccionado{selectedMembers.length !== 1 ? 's' : ''}
                            </div>

                            <div className="modal-footer">
                                <button
                                    className="btn btn-secondary"
                                    onClick={() => setStep(1)}
                                    disabled={loading}
                                >
                                    ← Atrás
                                </button>
                                <button
                                    className="btn btn-primary"
                                    onClick={handleCreateGroup}
                                    disabled={selectedMembers.length === 0 || loading}
                                >
                                    {loading ? 'Creando...' : 'Crear Grupo'}
                                </button>
                            </div>
                        </div>
                    )}
                </div>
            </div>
        </div>
    );
};

export default CreateGroupModal;
