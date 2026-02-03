import { useState, useEffect } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import API from '../../services/api';
import wsService from '../../services/websocket';
import './Chat.css';

const Sidebar = ({ 
    selectedChat, 
    chatType,
    onSelectUser, 
    onSelectGroup,
    onShowSettings,
    onCreateGroup,
    refreshKey
}) => {
    const { user, logout } = useAuth();
    const [users, setUsers] = useState([]);
    const [groups, setGroups] = useState([]);
    const [searchTerm, setSearchTerm] = useState('');
    const [loading, setLoading] = useState(true);
    const [showMenu, setShowMenu] = useState(false);
    const [onlineUsers, setOnlineUsers] = useState(new Set());

    useEffect(() => {
        loadUsers();
        loadGroups();
        requestOnlineUsers();
    }, [refreshKey]);

    useEffect(() => {
        // Escuchar eventos de usuarios online/offline
        const handleUserOnline = (data) => {
            if (data.users) {
                // Lista completa de usuarios online
                setOnlineUsers(new Set(data.users));
            } else if (data.user_id) {
                // Usuario específico se conectó
                setOnlineUsers(prev => new Set([...prev, data.user_id]));
            }
        };

        const handleUserOffline = (data) => {
            if (data.user_id) {
                setOnlineUsers(prev => {
                    const newSet = new Set(prev);
                    newSet.delete(data.user_id);
                    return newSet;
                });
            }
        };

        wsService.on('online', handleUserOnline);
        wsService.on('offline', handleUserOffline);

        return () => {
            wsService.off('online', handleUserOnline);
            wsService.off('offline', handleUserOffline);
        };
    }, []);

    useEffect(() => {
        // Cerrar menú al hacer clic fuera
        const handleClickOutside = (e) => {
            if (showMenu && !e.target.closest('.sidebar-actions')) {
                setShowMenu(false);
            }
        };

        document.addEventListener('click', handleClickOutside);
        return () => document.removeEventListener('click', handleClickOutside);
    }, [showMenu]);

    const loadUsers = async () => {
        try {
            const usersList = await API.getUsers();
            // Filtrar el usuario actual
            const otherUsers = usersList.filter(u => u.id !== user.id);
            setUsers(otherUsers);
        } catch (error) {
            // console.error('Error cargando usuarios:', error);
        } finally {
            setLoading(false);
        }
    };

    const loadGroups = async () => {
        try {
            const groupsList = await API.getMyGroups();
            setGroups(groupsList);
        } catch (error) {
            // console.error('Error cargando grupos:', error);
        }
    };

    const requestOnlineUsers = () => {
        wsService.send({ type: 'get_online_users' });
    };

    const filteredUsers = users.filter(u =>
        u.username.toLowerCase().includes(searchTerm.toLowerCase())
    );

    const filteredGroups = groups.filter(g =>
        g.name.toLowerCase().includes(searchTerm.toLowerCase())
    );

    // Combinar usuarios y grupos en una sola lista (grupos primero)
    const allChats = [
        ...filteredGroups.map(g => ({ ...g, type: 'group' })),
        ...filteredUsers.map(u => ({ ...u, type: 'user' }))
    ];

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

    const handleChatClick = (chat) => {
        if (chat.type === 'group') {
            onSelectGroup(chat);
        } else {
            onSelectUser(chat);
        }
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
                        className="btn-icon menu-button" 
                        onClick={() => setShowMenu(!showMenu)}
                        title="Menú"
                    >
                        <i className="fas fa-ellipsis-v"></i>
                    </button>
                    {showMenu && (
                        <div className="dropdown-menu">
                            <button onClick={() => { onCreateGroup(); setShowMenu(false); }}>
                                <i className="fas fa-plus"></i> Crear Grupo
                            </button>
                            {/* <button onClick={() => { onShowSettings(); setShowMenu(false); }}>
                                <i className="fas fa-cog"></i> Configuración
                            </button> */}
                            <button onClick={logout} className="logout-btn">
                                <i className="fas fa-sign-out-alt"></i> Cerrar Sesión
                            </button>
                        </div>
                    )}
                </div>
            </div>

            <div className="search-box">
                <i className="fas fa-search"></i>
                <input
                    type="text"
                    placeholder="Buscar chats..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                />
            </div>

            {/* Lista unificada de chats */}
            <div className="users-list">
                {loading ? (
                    <div className="loading-users">
                        <i className="fas fa-spinner fa-spin"></i>
                        <p>Cargando chats...</p>
                    </div>
                ) : allChats.length === 0 ? (
                    <div className="no-users">
                        <i className="fas fa-comments"></i>
                        <p>No hay chats disponibles</p>
                    </div>
                ) : (
                    allChats.map((chat) => (
                        chat.type === 'group' ? (
                            <div
                                key={`group-${chat.id}`}
                                className={`user-item ${chatType === 'group' && selectedChat?.id === chat.id ? 'active' : ''}`}
                                onClick={() => handleChatClick(chat)}
                            >
                                <div className="user-avatar group-avatar">
                                    <i className="fas fa-users"></i>
                                </div>
                                <div className="user-item-info">
                                    <h4>{chat.name}</h4>
                                    <p className="user-email">
                                        {chat.member_count || 0} miembro{chat.member_count !== 1 ? 's' : ''}
                                    </p>
                                </div>
                            </div>
                        ) : (
                            <div
                                key={`user-${chat.id}`}
                                className={`user-item ${chatType === 'user' && selectedChat?.id === chat.id ? 'active' : ''}`}
                                onClick={() => handleChatClick(chat)}
                            >
                                <div 
                                    className="user-avatar"
                                    style={{ background: getAvatarGradient(chat.id) }}
                                >
                                    <i className="fas fa-user"></i>
                                </div>
                                <div className="user-item-info">
                                    <h4>{chat.username}</h4>
                                    <p className={`user-status ${onlineUsers.has(chat.id) ? 'online' : 'offline'}`}>
                                        <span className="status-dot"></span>
                                        {onlineUsers.has(chat.id) ? 'En línea' : 'Desconectado'}
                                    </p>
                                </div>
                            </div>
                        )
                    ))
                )}
            </div>
        </div>
    );
};

export default Sidebar;
