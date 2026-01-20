import { useState } from 'react';
import Sidebar from './Sidebar';
import ChatArea from './ChatArea';
import SettingsModal from '../Common/SettingsModal';
import EncryptionInfoModal from '../Common/EncryptionInfoModal';
import './Chat.css';

const ChatPage = () => {
    const [selectedUser, setSelectedUser] = useState(null);
    const [showSettings, setShowSettings] = useState(false);
    const [showEncryptionInfo, setShowEncryptionInfo] = useState(false);

    const handleSelectUser = (user) => {
        setSelectedUser(user);
    };

    const handleBackToContacts = () => {
        setSelectedUser(null);
    };

    return (
        <div className="chat-screen">
            <div className={`chat-container ${selectedUser ? 'chat-open' : 'contacts-view'}`}>
                <Sidebar
                    selectedUser={selectedUser}
                    onSelectUser={handleSelectUser}
                    onShowSettings={() => setShowSettings(true)}
                />
                <ChatArea
                    selectedUser={selectedUser}
                    onShowEncryptionInfo={() => setShowEncryptionInfo(true)}
                    onBack={handleBackToContacts}
                />
            </div>

            {showSettings && (
                <SettingsModal onClose={() => setShowSettings(false)} />
            )}

            {showEncryptionInfo && (
                <EncryptionInfoModal onClose={() => setShowEncryptionInfo(false)} />
            )}
        </div>
    );
};

export default ChatPage;
