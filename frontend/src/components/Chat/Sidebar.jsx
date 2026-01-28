import { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import API from '../../services/api';
import './Chat.css';

const Sidebar = ({ 
    selectedChat, 
    chatType,
    onSelectUser, 
    onSelectGroup,
    onShowSettings,
    onCreateGroup,
    onJoinGroup,
    refreshKey
}) => {
    const { user, logout } = useAuth();
    const [users, setUsers] = useState([]);
    const [groups, setGroups] = useState([]);
    const [searchTerm, setSearchTerm] = useState('');
    const [loading, setLoading] = useState(true);
    const [activeTab, setActiveTab] = useState('users'); // 'users' o 'groups'

    useEffect(() => {
        loadUsers();
        loadGroups();
    }, [refreshKey]);

    const loadUsers = async () => {
        try {
            const usersList = await API.getUsers();
            // Filtrar el usuario actual
            const otherUsers = usersList.filter(u => u.id !== user.id);
            setUsers(otherUsers);
        } catch (error) {
            console.error('Error cargando usuarios:', error);
        } finally {
            setLoading(false);
        }
    };

    const loadGroups = async () => {
        try {
            const groupsList = await API.getMyGroups();
            setGroups(groupsList);
        } catch (error) {
            console.error('Error cargando grupos:', error);
        }
    };

    const filteredUsers = users.filter(u =>
        u.username.toLowerCase().includes(searchTerm.toLowerCase())
    );

    const filteredGroups = groups.filter(g =>
        g.name.toLowerCase().includes(searchTerm.toLowerCase())
    );

    const getAvatarGradient = (userId) => {
        const gradients = [
            ['#667eea', '#764ba2'],
            ['#f093fb', '#f5576c'],
            ['#4facfe', '#00f2fe'],
            ['#43e97b', '#38f9d7'],
            ['#fa709a', '#fee140'],
            ['#30cfd0', '#330867'],
            ['#a8edea', '#fed6e3'],
            ['#ff9a56', '#ff6a88'],
        ];
        const index = userId % gradients.length;
        return `linear-gradient(135deg, ${gradients[index][0]}, ${gradients[index][1]})`;
    };

    return (
        <div className="sidebar">
            <div className="sidebar-header">
                <div className="user-info">
                    <div 
                        className="user-avatar"
                        style={{ background: getAvatarGradient(user?.id || 0) }}
                    >
                        <i className="fas fa-user"></i>
                    </div>
                    <div className="user-details">
                        <h3>{user?.username}</h3>
                        <span className="status online">En línea</span>
                    </div>
                </div>
                <div className="sidebar-actions">
                    <button 
                        className="btn-icon" 
                        onClick={onShowSettings}
                        title="Configuración"
                    >
                        <i className="fas fa-cog"></i>
                    </button>
                    <button 
                        className="btn-icon" 
                        onClick={logout}
                        title="Cerrar sesión"
                    >
                        <i className="fas fa-sign-out-alt"></i>
                    </button>
                </div>
            </div>

            {/* Tabs para cambiar entre usuarios y grupos */}
            <div className="sidebar-tabs">
                <button
                    className={`tab ${activeTab === 'users' ? 'active' : ''}`}
                    onClick={() => setActiveTab('users')}
                >
                    <i className="fas fa-user"></i> Usuarios
                </button>
                <button
                    className={`tab ${activeTab === 'groups' ? 'active' : ''}`}
                    onClick={() => setActiveTab('groups')}
                >
                    <i className="fas fa-users"></i> Grupos
                </button>
            </div>

            <div className="search-box">
                <i className="fas fa-search"></i>
                <input
                    type="text"
                    placeholder={activeTab === 'users' ? 'Buscar usuarios...' : 'Buscar grupos...'}
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                />
            </div>

            {/* Botones de acción para grupos */}
            {activeTab === 'groups' && (
                <div className="group-actions">
                    <button className="btn btn-primary btn-sm" onClick={onCreateGroup}>
                        <i className="fas fa-plus"></i> Crear Grupo
                    </button>
                    <button className="btn btn-secondary btn-sm" onClick={onJoinGroup}>
                        <i className="fas fa-sign-in-alt"></i> Unirse
                    </button>
                </div>
            )}

            {/* Lista de usuarios */}
            {activeTab === 'users' && (
                <div className="users-list">
                    {loading ? (
                        <div className="loading-users">
                            <i className="fas fa-spinner fa-spin"></i>
                            <p>Cargando usuarios...</p>
                        </div>
                    ) : filteredUsers.length === 0 ? (
                        <div className="no-users">
                            <i className="fas fa-users"></i>
                            <p>No se encontraron usuarios</p>
                        </div>
                    ) : (
                        filteredUsers.map((u) => (
                            <div
                                key={u.id}
                                className={`user-item ${chatType === 'user' && selectedChat?.id === u.id ? 'active' : ''}`}
                                onClick={() => onSelectUser(u)}
                            >
                                <div 
                                    className="user-avatar"
                                    style={{ background: getAvatarGradient(u.id) }}
                                >
                                    <i className="fas fa-user"></i>
                                </div>
                                <div className="user-item-info">
                                    <h4>{u.username}</h4>
                                    <p className="user-email">{u.email}</p>
                                </div>
                                {u.is_online && (
                                    <span className="online-indicator"></span>
                                )}
                            </div>
                        ))
                    )}
                </div>
            )}

            {/* Lista de grupos */}
            {activeTab === 'groups' && (
                <div className="users-list">
                    {loading ? (
                        <div className="loading-users">
                            <i className="fas fa-spinner fa-spin"></i>
                            <p>Cargando grupos...</p>
                        </div>
                    ) : filteredGroups.length === 0 ? (
                        <div className="no-users">
                            <i className="fas fa-users"></i>
                            <p>No tienes grupos aún</p>
                            <button 
                                className="btn btn-primary btn-sm" 
                                onClick={onCreateGroup}
                                style={{ marginTop: '10px' }}
                            >
                                Crear tu primer grupo
                            </button>
                        </div>
                    ) : (
                        filteredGroups.map((group) => (
                            <div
                                key={group.id}
                                className={`group-list-item ${chatType === 'group' && selectedChat?.id === group.id ? 'active' : ''}`}
                                onClick={() => onSelectGroup(group)}
                            >
                                <div className="group-icon">
                                    <i className="fas fa-users"></i>
                                </div>
                                <div className="group-info">
                                    <div className="group-name">{group.name}</div>
                                    <div className="group-members-count">
                                        {group.member_count || 0} miembro{group.member_count !== 1 ? 's' : ''}
                                    </div>
                                </div>
                            </div>
                        ))
                    )}
                </div>
            )}
        </div>

    );
};

export default Sidebar;
