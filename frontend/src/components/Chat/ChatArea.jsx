import { useState, useEffect, useRef } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import API from '../../services/api';
import wsService from '../../services/websocket';
import CryptoModule from '../../utils/crypto';
import CONFIG from '../../utils/config';
import './Chat.css';

const ChatArea = ({ selectedUser, onShowEncryptionInfo, onBack }) => {
    const { user, privateKey } = useAuth();
    const [messages, setMessages] = useState([]);
    const [messageText, setMessageText] = useState('');
    const [loading, setLoading] = useState(false);
    const [sending, setSending] = useState(false);
    const [typingUser, setTypingUser] = useState(null);
    const messagesEndRef = useRef(null);
    const typingTimeoutRef = useRef(null);

    useEffect(() => {
        if (selectedUser) {
            loadMessages();
        }
    }, [selectedUser]);

    useEffect(() => {
        // Escuchar nuevos mensajes
        const handleNewMessage = (data) => {
            if (data.sender_id === selectedUser?.id || data.recipient_id === selectedUser?.id) {
                decryptAndAddMessage(data);
            }
        };

        const handleTyping = (data) => {
            if (data.user_id === selectedUser?.id) {
                setTypingUser(data.username);
                setTimeout(() => setTypingUser(null), 3000);
            }
        };

        wsService.on('message', handleNewMessage);
        wsService.on('typing', handleTyping);

        return () => {
            wsService.off('message', handleNewMessage);
            wsService.off('typing', handleTyping);
        };
    }, [selectedUser, privateKey]);

    useEffect(() => {
        scrollToBottom();
    }, [messages]);

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    };

    const loadMessages = async () => {
        if (!selectedUser) return;

        setLoading(true);
        try {
            const messagesData = await API.getMessages(selectedUser.id);
            
            // Descifrar todos los mensajes
            const decryptedMessages = await Promise.all(
                messagesData.map(async (msg) => {
                    try {
                        const isSender = msg.sender_id === user.id;
                        
                        let encryptedContent, encryptedKey, iv;
                        
                        if (isSender && msg.sender_encrypted_message) {
                            encryptedContent = msg.sender_encrypted_message;
                            encryptedKey = msg.sender_encrypted_key;
                            iv = msg.sender_iv;
                        } else {
                            encryptedContent = msg.encrypted_content;
                            encryptedKey = msg.encrypted_aes_key;
                            iv = msg.iv;
                        }
                        
                        const decryptedText = await CryptoModule.decryptMessage(
                            {
                                encrypted_message: encryptedContent,
                                encrypted_key: encryptedKey,
                                iv: iv
                            },
                            privateKey
                        );
                        return { 
                            ...msg, 
                            text: decryptedText,
                            created_at: msg.timestamp 
                        };
                    } catch (error) {
                        console.error('Error descifrando mensaje:', error);
                        return { 
                            ...msg, 
                            text: '[Error descifrando mensaje]',
                            created_at: msg.timestamp 
                        };
                    }
                })
            );

            setMessages(decryptedMessages);
        } catch (error) {
            console.error('Error cargando mensajes:', error);
        } finally {
            setLoading(false);
        }
    };

    const decryptAndAddMessage = async (encryptedMessage) => {
        try {
            const encData = encryptedMessage.encrypted_data || encryptedMessage;
            
            const decryptedText = await CryptoModule.decryptMessage(
                {
                    encrypted_message: encData.encrypted_message || encData.encrypted_content,
                    encrypted_key: encData.encrypted_key || encData.encrypted_aes_key,
                    iv: encData.iv
                },
                privateKey
            );

            const newMessage = {
                id: encryptedMessage.message_id,
                sender_id: encryptedMessage.sender_id,
                recipient_id: selectedUser.id,
                text: decryptedText,
                created_at: encryptedMessage.timestamp,
                timestamp: encryptedMessage.timestamp
            };

            setMessages((prev) => [...prev, newMessage]);
        } catch (error) {
            console.error('Error descifrando nuevo mensaje:', error);
        }
    };

    const handleSendMessage = async (e) => {
        e.preventDefault();

        if (!messageText.trim() || !selectedUser) return;

        setSending(true);

        try {
            console.group('📤 ENVIANDO MENSAJE');
            console.log('Destinatario:', selectedUser.username, '(ID:', selectedUser.id, ')');
            console.log('Mensaje original:', messageText);
            
            // Obtener clave pública del destinatario
            console.log('\n🔑 Obteniendo clave pública del destinatario...');
            const recipientKeyData = await API.getUserPublicKey(selectedUser.id);
            console.log('✓ Clave pública obtenida:', recipientKeyData.public_key_rsa.substring(0, 50) + '...');

            // Cifrar mensaje PARA EL RECEPTOR
            console.log('\n🔐 [1/2] Cifrando mensaje para el receptor...');
            const encryptedForRecipient = await CryptoModule.encryptMessage(
                messageText,
                recipientKeyData.public_key_rsa
            );
            console.log('✓ Mensaje cifrado para receptor:', encryptedForRecipient.encrypted_message.substring(0, 30) + '...');

            console.log('\n🔐 [2/2] Cifrando mensaje para mí mismo...');
            const myPublicKey = user.public_key_rsa;
            const encryptedForSender = await CryptoModule.encryptMessage(
                messageText,
                myPublicKey
            );
            console.log('✓ Mensaje cifrado para mí:', encryptedForSender.encrypted_message.substring(0, 30) + '...');

            // Firmar mensaje con clave privada del emisor
            console.log('\n✍️ Firmando mensaje con RSA-PSS...');
            const privateKey = localStorage.getItem(CONFIG.STORAGE_KEYS.PRIVATE_KEY);
            if (!privateKey) {
                throw new Error('No se encontró la clave privada para firmar el mensaje');
            }
            
            const signature = await CryptoModule.signMessage(messageText, privateKey);
            console.log('✓ Firma digital:', signature.substring(0, 50) + '...');

            // Preparar payload para WebSocket con AMBAS versiones cifradas
            const wsPayload = {
                type: 'message',
                recipient_id: selectedUser.id,
                encrypted_data: {
                    // Versión para el receptor
                    encrypted_message: encryptedForRecipient.encrypted_message,
                    encrypted_key: encryptedForRecipient.encrypted_key,
                    iv: encryptedForRecipient.iv,
                    nonce: encryptedForRecipient.nonce,
                    signature: signature,
                    // Versión para el emisor (yo mismo)
                    sender_encrypted_message: encryptedForSender.encrypted_message,
                    sender_encrypted_key: encryptedForSender.encrypted_key,
                    sender_iv: encryptedForSender.iv
                }
            };
            
            console.log('\n📡 Enviando por WebSocket...');
            console.log('Payload completo:', JSON.stringify(wsPayload, null, 2));

            // Enviar mensaje por WebSocket
            wsService.send(wsPayload);
            
            console.log('✓ Mensaje enviado al servidor');
            console.groupEnd();

            // Agregar a la lista local optimistamente
            const now = new Date().toISOString();
            setMessages((prev) => [...prev, {
                id: Date.now(), // ID temporal
                text: messageText,
                sender_id: user.id,
                recipient_id: selectedUser.id,
                created_at: now,
                timestamp: now
            }]);

            setMessageText('');
        } catch (error) {
            console.groupEnd();
            console.error('❌ Error enviando mensaje:', error);
            alert('Error enviando mensaje: ' + error.message);
        } finally {
            setSending(false);
        }
    };

    const handleTyping = () => {
        if (selectedUser) {
            wsService.sendTyping(selectedUser.id);
        }

        if (typingTimeoutRef.current) {
            clearTimeout(typingTimeoutRef.current);
        }
    };

    const formatTime = (timestamp) => {
        const date = new Date(timestamp);
        return date.toLocaleTimeString('es-ES', { hour: '2-digit', minute: '2-digit' });
    };

    if (!selectedUser) {
        return (
            <div className="chat-area">
                <div className="no-chat-selected">
                    <i className="fas fa-comments"></i>
                    <h3>Bienvenido a SecureChat</h3>
                    <p>Selecciona un usuario para comenzar a conversar</p>
                    <div className="security-features">
                        <div className="feature">
                            <i className="fas fa-shield-alt"></i>
                            <span>Cifrado End-to-End</span>
                        </div>
                        <div className="feature">
                            <i className="fas fa-signature"></i>
                            <span>Firmas Digitales</span>
                        </div>
                        <div className="feature">
                            <i className="fas fa-user-shield"></i>
                            <span>Autenticación 2FA</span>
                        </div>
                    </div>
                </div>
            </div>
        );
    }

    return (
        <div className="chat-area">
            <div className="chat-header">
                <button 
                    className="btn-back-mobile" 
                    onClick={onBack}
                    title="Volver a contactos"
                >
                    <i className="fas fa-arrow-left"></i>
                </button>
                <div className="chat-user-info">
                    <div className="user-avatar">
                        <i className="fas fa-user-circle"></i>
                    </div>
                    <div>
                        <h3>{selectedUser.username}</h3>
                        {typingUser && (
                            <span className="typing-indicator">
                                <i className="fas fa-circle-notch fa-spin"></i> Escribiendo...
                            </span>
                        )}
                    </div>
                </div>
                <div className="chat-actions">
                    <button 
                        className="btn-icon" 
                        onClick={onShowEncryptionInfo}
                        title="Información de cifrado"
                    >
                        <i className="fas fa-lock"></i>
                    </button>
                </div>
            </div>

            <div className="messages-container">
                {loading ? (
                    <div className="loading-messages">
                        <i className="fas fa-spinner fa-spin"></i>
                        <p>Cargando mensajes...</p>
                    </div>
                ) : (
                    <div className="messages">
                        {messages.map((msg, index) => (
                            <div
                                key={msg.id || index}
                                className={`message ${msg.sender_id === user.id ? 'sent' : 'received'}`}
                            >
                                <div className="message-content">
                                    <p>{msg.text}</p>
                                    <span className="message-time">
                                        {formatTime(msg.created_at)}
                                    </span>
                                </div>
                            </div>
                        ))}
                        <div ref={messagesEndRef} />
                    </div>
                )}
            </div>

            <div className="message-input-container">
                <form onSubmit={handleSendMessage} className="message-form">
                    <button type="button" className="btn-icon" title="Adjuntar archivo">
                        <i className="fas fa-paperclip"></i>
                    </button>
                    <input
                        type="text"
                        value={messageText}
                        onChange={(e) => setMessageText(e.target.value)}
                        onKeyUp={handleTyping}
                        placeholder="Escribe un mensaje cifrado..."
                        disabled={sending}
                    />
                    <button 
                        type="submit" 
                        className="btn-send"
                        disabled={sending || !messageText.trim()}
                    >
                        <i className="fas fa-paper-plane"></i>
                    </button>
                </form>
                <div className="encryption-status">
                    <i className="fas fa-lock"></i>
                    <span>Mensajes cifrados de extremo a extremo</span>
                </div>
            </div>
        </div>
    );
};

export default ChatArea;
