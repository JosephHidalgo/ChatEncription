import { useState } from 'react';
import Sidebar from './Sidebar';
import ChatArea from './ChatArea';
import SettingsModal from '../Common/SettingsModal';
import EncryptionInfoModal from '../Common/EncryptionInfoModal';
import CreateGroupModal from './CreateGroupModal';
import JoinGroupModal from './JoinGroupModal';
import GroupDetailsModal from './GroupDetailsModal';
import { useAuth } from '../../contexts/AuthContext';
import './Chat.css';

const ChatPage = () => {
    const { user } = useAuth();
    const [selectedChat, setSelectedChat] = useState(null); // Puede ser user o group
    const [chatType, setChatType] = useState(null); // 'user' o 'group'
    const [showSettings, setShowSettings] = useState(false);
    const [showEncryptionInfo, setShowEncryptionInfo] = useState(false);
    const [showCreateGroup, setShowCreateGroup] = useState(false);
    const [showJoinGroup, setShowJoinGroup] = useState(false);
    const [showGroupDetails, setShowGroupDetails] = useState(false);
    const [refreshSidebar, setRefreshSidebar] = useState(0);

    const handleSelectUser = (user) => {
        setSelectedChat(user);
        setChatType('user');
        setShowGroupDetails(false);
    };

    const handleSelectGroup = (group) => {
        setSelectedChat(group);
        setChatType('group');
        setShowGroupDetails(false);
    };

    const handleShowGroupDetails = () => {
        if (chatType === 'group') {
            setShowGroupDetails(true);
        }
    };

    const handleBackToContacts = () => {
        setSelectedChat(null);
        setChatType(null);
        setShowGroupDetails(false);
    };

    const handleGroupCreated = (group) => {
        setRefreshSidebar(prev => prev + 1);
        setSelectedChat(group);
        setChatType('group');
    };

    const handleGroupJoined = (group) => {
        setRefreshSidebar(prev => prev + 1);
        setSelectedChat(group);
        setChatType('group');
    };

    const handleRefreshGroup = () => {
        setRefreshSidebar(prev => prev + 1);
    };

    return (
        <div className="chat-screen">
            <div className={`chat-container ${selectedChat ? 'chat-open' : 'contacts-view'}`}>
                <Sidebar
                    selectedChat={selectedChat}
                    chatType={chatType}
                    onSelectUser={handleSelectUser}
                    onSelectGroup={handleSelectGroup}
                    onShowSettings={() => setShowSettings(true)}
                    onCreateGroup={() => setShowCreateGroup(true)}
                    onJoinGroup={() => setShowJoinGroup(true)}
                    refreshKey={refreshSidebar}
                />
                <ChatArea
                    selectedChat={selectedChat}
                    chatType={chatType}
                    onShowEncryptionInfo={() => setShowEncryptionInfo(true)}
                    onShowGroupDetails={handleShowGroupDetails}
                    onBack={handleBackToContacts}
                />
            </div>

            {showSettings && (
                <SettingsModal onClose={() => setShowSettings(false)} />
            )}

            {showEncryptionInfo && (
                <EncryptionInfoModal onClose={() => setShowEncryptionInfo(false)} />
            )}

            {showCreateGroup && (
                <CreateGroupModal
                    isOpen={showCreateGroup}
                    onClose={() => setShowCreateGroup(false)}
                    onGroupCreated={handleGroupCreated}
                    currentUser={user}
                />
            )}

            {showJoinGroup && (
                <JoinGroupModal
                    isOpen={showJoinGroup}
                    onClose={() => setShowJoinGroup(false)}
                    onGroupJoined={handleGroupJoined}
                    currentUser={user}
                />
            )}

            {showGroupDetails && chatType === 'group' && (
                <GroupDetailsModal
                    isOpen={showGroupDetails}
                    onClose={() => setShowGroupDetails(false)}
                    group={selectedChat}
                    currentUser={user}
                    onRefresh={handleRefreshGroup}
                />
            )}
        </div>
    );
};

export default ChatPage;
