import { useState, useEffect, useRef } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import API from '../../services/api';
import wsService from '../../services/websocket';
import CryptoModule from '../../utils/crypto';
import CONFIG from '../../utils/config';
import './Chat.css';

const ChatArea = ({
    selectedChat,
    chatType,
    onShowEncryptionInfo,
    onBack,
    onShowGroupDetails
}) => {
    console.log('🎨 [ChatArea] Componente renderizado', { selectedChat, chatType });
    console.log('   selectedChat ID:', selectedChat?.id);
    console.log('   chatType:', chatType);

    const { user, privateKey } = useAuth();
    const [messages, setMessages] = useState([]);
    const [messageText, setMessageText] = useState('');
    const [loading, setLoading] = useState(false);
    const [sending, setSending] = useState(false);
    const [typingUser, setTypingUser] = useState(null);
    const messagesEndRef = useRef(null);
    const typingTimeoutRef = useRef(null);

    // Refs para mantener valores actualizados en los listeners
    const selectedChatRef = useRef(selectedChat);
    const chatTypeRef = useRef(chatType);

    // Determinar el chat activo
    const activeChat = selectedChat;
    const selectedUser = chatType === 'user' ? selectedChat : null;
    const selectedGroup = chatType === 'group' ? selectedChat : null;
    const chatId = selectedChat?.id;

    // Actualizar refs cuando cambien los valores
    useEffect(() => {
        console.log('📍 [ChatArea] useEffect de refs ejecutado');
        selectedChatRef.current = selectedChat;
        chatTypeRef.current = chatType;
    }, [selectedChat, chatType]);

    useEffect(() => {
        if (activeChat) {
            loadMessages();

            // Si es grupo, unirse a la sala WebSocket
            if (chatType === 'group' && selectedGroup) {
                wsService.joinGroup(selectedGroup.id);
            }
        }

        return () => {
            // Si es grupo, salir de la sala WebSocket
            if (chatType === 'group' && selectedGroup) {
                wsService.leaveGroup(selectedGroup.id);
            }
        };
    }, [activeChat, chatType]);

    useEffect(() => {
        console.log('🔄 [ChatArea] useEffect de listeners ejecutado');
        console.log('   chatType:', chatType);
        console.log('   selectedChat:', selectedChat);

        if (!chatType || !selectedChat) {
            console.log('   ⚠️ No hay chat seleccionado, saltando configuración de listeners');
            return;
        }

        // Registrar listeners solo una vez cuando el componente se monta
        // Los handlers usarán refs para acceder a los valores actualizados

        if (chatType === 'user') {
            console.log('   → Configurando listeners de usuario');
            console.log('   Usuario actual (yo):', user.id, user.username);

            const handleNewMessage = (data) => {
                console.log('📨 [ChatArea] Mensaje privado recibido:', data);
                const currentSelectedUser = selectedChatRef.current;
                console.log('   Usuario seleccionado:', currentSelectedUser?.id, currentSelectedUser?.username);
                console.log('   Yo:', user.id);

                // Verificar si el mensaje es de/para el usuario seleccionado
                const isFromSelected = data.sender_id === currentSelectedUser?.id;
                const isToSelected = data.recipient_id === currentSelectedUser?.id;
                const isFromMe = data.sender_id === user.id;
                const isToMe = data.recipient_id === user.id;

                console.log('   isFromSelected:', isFromSelected);
                console.log('   isToSelected:', isToSelected);
                console.log('   isFromMe:', isFromMe);
                console.log('   isToMe:', isToMe);

                // Mostrar el mensaje si es una conversación con el usuario seleccionado
                if ((isFromSelected && isToMe) || (isFromMe && isToSelected)) {
                    console.log('✓ Mensaje es parte de esta conversación, procesando...');
                    decryptAndAddUserMessage(data);
                } else {
                    console.log('⚠️ Mensaje NO es parte de esta conversación, ignorando');
                }
            };

            const handleTyping = (data) => {
                console.log('⌨️ [ChatArea] Notificación de typing recibida:', data);
                const currentUser = selectedChatRef.current;
                console.log('   Usuario seleccionado:', currentUser?.id);
                console.log('   Sender ID:', data.sender_id);
                
                if (data.sender_id === currentUser?.id) {
                    console.log('✓ Mostrando indicador de typing');
                    setTypingUser(data.sender_username);
                    setTimeout(() => setTypingUser(null), 3000);
                } else {
                    console.log('⚠️ Typing de otro usuario, ignorando');
                }
            };

            wsService.on('message', handleNewMessage);
            wsService.on('typing', handleTyping);

            return () => {
                console.log('🧹 [ChatArea] Limpiando listeners de usuario');
                wsService.off('message', handleNewMessage);
                wsService.off('typing', handleTyping);
            };

        } else if (chatType === 'group') {
            console.log('   → Configurando listeners de grupo');
            console.log('   Grupo ID:', selectedChat.id);

            const handleGroupMessage = (data) => {
                console.log('🔔 Listener de grupo activado. Data:', data);
                const currentGroup = selectedChatRef.current;
                const currentChatType = chatTypeRef.current;

                console.log('   Grupo del mensaje:', data.group_id);
                console.log('   Grupo seleccionado (ref):', currentGroup?.id);
                console.log('   Tipo de chat (ref):', currentChatType);

                if (currentChatType === 'group' && data.group_id === currentGroup?.id) {
                    console.log('✓ El mensaje es para este grupo, procesando...');
                    decryptAndAddGroupMessage(data);
                } else {
                    console.log('⚠️ El mensaje NO es para este grupo, ignorando');
                }
            };

            const handleGroupTyping = (data) => {
                const currentGroup = selectedChatRef.current;
                const currentChatType = chatTypeRef.current;

                if (currentChatType === 'group' && data.group_id === currentGroup?.id && data.sender_id !== user.id) {
                    setTypingUser(data.sender_username);
                    setTimeout(() => setTypingUser(null), 3000);
                }
            };

            console.log('   📝 Registrando listeners...');
            console.log('   wsService:', wsService);
            console.log('   wsService.on:', typeof wsService.on);
            wsService.on('group_message', handleGroupMessage);
            wsService.on('group_typing', handleGroupTyping);
            console.log('   ✅ Listeners registrados');

            return () => {
                console.log('🧹 [ChatArea] Limpiando listeners de grupo');
                wsService.off('group_message', handleGroupMessage);
                wsService.off('group_typing', handleGroupTyping);
            };
        }
    }, [chatType, selectedChat?.id]);

    useEffect(() => {
        scrollToBottom();
    }, [messages]);

    useEffect(() => {
        scrollToBottom();
    }, [typingUser]);

    const scrollToBottom = () => {
        messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    };

    const loadMessages = async () => {
        if (!activeChat) return;

        setLoading(true);
        try {
            if (chatType === 'user') {
                await loadUserMessages();
            } else if (chatType === 'group') {
                await loadGroupMessages();
            }
        } catch (error) {
            console.error('Error cargando mensajes:', error);
        } finally {
            setLoading(false);
        }
    };

    const loadUserMessages = async () => {
        const messagesData = await API.getMessages(selectedUser.id);

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
    };

    const loadGroupMessages = async () => {
        const messagesData = await API.getGroupMessages(selectedGroup.id);

        // Obtener la clave del grupo desde localStorage
        const storageKey = CONFIG.STORAGE_KEYS.GROUP_KEY_PREFIX + selectedGroup.id;
        console.log('🔍 Cargando mensajes del grupo. Buscando clave con key:', storageKey);

        let groupKeyHex = localStorage.getItem(storageKey);
        console.log('🔑 Clave encontrada en localStorage:', groupKeyHex ? (groupKeyHex.substring(0, 32) + '...') : 'NO ENCONTRADA');

        // Si no está en localStorage, obtenerla del servidor
        if (!groupKeyHex) {
            console.log('📡 Obteniendo clave del grupo desde el servidor...');
            try {
                const encryptedKeyData = await API.getMyEncryptedGroupKey(selectedGroup.id);
                console.log('✓ Clave encriptada recibida del servidor');

                // Desencriptar la clave del grupo con nuestra clave privada RSA
                const decryptedKeyBuffer = await CryptoModule.decryptRSA(
                    encryptedKeyData.encrypted_group_key,
                    privateKey
                );

                // Convertir buffer a hex string
                const decoder = new TextDecoder();
                groupKeyHex = decoder.decode(decryptedKeyBuffer);

                console.log('✓ Clave del grupo descifrada:', groupKeyHex.substring(0, 32) + '...');

                // Guardar en localStorage para futuras sesiones
                localStorage.setItem(storageKey, groupKeyHex);
                console.log('✓ Clave guardada en localStorage');
            } catch (error) {
                console.error('❌ Error obteniendo/descifrando clave del grupo:', error);
                setMessages([]);
                return;
            }
        }

        const decryptedMessages = await Promise.all(
            messagesData.map(async (msg) => {
                try {
                    const decryptedText = await CryptoModule.decryptGroupMessage(
                        msg.encrypted_content,
                        msg.iv,
                        groupKeyHex
                    );

                    return {
                        ...msg,
                        text: decryptedText,
                        created_at: msg.timestamp,
                        isMine: msg.sender_id === user.id
                    };
                } catch (error) {
                    console.error('Error descifrando mensaje grupal:', error);
                    return {
                        ...msg,
                        text: '[Error descifrando mensaje]',
                        created_at: msg.timestamp,
                        isMine: msg.sender_id === user.id
                    };
                }
            })
        );

        setMessages(decryptedMessages);
    };

    const decryptAndAddUserMessage = async (encryptedMessage) => {
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

    const decryptAndAddGroupMessage = async (data) => {
        console.group('📨 PROCESANDO MENSAJE GRUPAL RECIBIDO');
        console.log('Data recibida:', data);
        console.log('Grupo actual:', selectedGroup?.id);
        console.log('¿Coincide con grupo actual?:', data.group_id === selectedGroup?.id);

        // Verificar que el mensaje tenga los datos necesarios
        if (!data.encrypted_content || !data.iv) {
            console.warn('⚠️ Mensaje sin encrypted_content o iv, ignorando');
            console.log('   encrypted_content:', data.encrypted_content);
            console.log('   iv:', data.iv);
            console.groupEnd();
            return;
        }

        try {
            const storageKey = CONFIG.STORAGE_KEYS.GROUP_KEY_PREFIX + selectedGroup.id;
            let groupKeyHex = localStorage.getItem(storageKey);
            console.log('🔑 Clave del grupo:', groupKeyHex ? 'ENCONTRADA' : 'NO ENCONTRADA');

            // Si no está en localStorage, obtenerla del servidor
            if (!groupKeyHex) {
                console.log('📡 Obteniendo clave del grupo desde el servidor para mensaje en tiempo real...');
                try {
                    const encryptedKeyData = await API.getMyEncryptedGroupKey(selectedGroup.id);
                    const decryptedKeyBuffer = await CryptoModule.decryptRSA(
                        encryptedKeyData.encrypted_group_key,
                        privateKey
                    );
                    const decoder = new TextDecoder();
                    groupKeyHex = decoder.decode(decryptedKeyBuffer);
                    localStorage.setItem(storageKey, groupKeyHex);
                    console.log('✓ Clave del grupo obtenida y guardada');
                } catch (error) {
                    console.error('❌ Error obteniendo clave del grupo:', error);
                    console.groupEnd();
                    return;
                }
            }

            console.log('🔓 Descifrando mensaje...');
            const decryptedText = await CryptoModule.decryptGroupMessage(
                data.encrypted_content,
                data.iv,
                groupKeyHex
            );
            console.log('✓ Mensaje descifrado:', decryptedText);

            const newMessage = {
                id: data.message_id,
                sender_id: data.sender_id,
                sender_username: data.sender_username,
                group_id: selectedGroup.id,
                text: decryptedText,
                created_at: data.timestamp,
                isMine: data.sender_id === user.id
            };

            console.log('➕ Agregando mensaje al estado');
            setMessages((prev) => {
                console.log('Mensajes anteriores:', prev.length);
                const updated = [...prev, newMessage];
                console.log('Mensajes actualizados:', updated.length);
                return updated;
            });
            console.log('✅ Mensaje agregado exitosamente');
            console.groupEnd();
        } catch (error) {
            console.error('❌ Error descifrando mensaje grupal:', error);
            console.groupEnd();
        }
    };

    const handleSendMessage = async (e) => {
        e.preventDefault();

        if (!messageText.trim() || !activeChat) return;

        setSending(true);

        try {
            if (chatType === 'user') {
                await sendUserMessage();
            } else if (chatType === 'group') {
                await sendGroupMessage();
            }

            setMessageText('');
        } catch (error) {
            console.error('Error enviando mensaje:', error);
            alert('Error al enviar el mensaje. Por favor intenta nuevamente.');
        } finally {
            setSending(false);
        }
    };

    const sendUserMessage = async () => {
        console.group('📤 ENVIANDO MENSAJE A USUARIO');
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
        const privateKeyPem = localStorage.getItem(CONFIG.STORAGE_KEYS.PRIVATE_KEY);
        if (!privateKeyPem) {
            throw new Error('No se encontró la clave privada para firmar el mensaje');
        }

        const signature = await CryptoModule.signMessage(messageText, privateKeyPem);
        console.log('✓ Firma digital:', signature.substring(0, 50) + '...');

        // Preparar payload para WebSocket con AMBAS versiones cifradas
        const wsPayload = {
            type: 'message',
            recipient_id: selectedUser.id,
            encrypted_data: {
                encrypted_message: encryptedForRecipient.encrypted_message,
                encrypted_key: encryptedForRecipient.encrypted_key,
                iv: encryptedForRecipient.iv,
                nonce: encryptedForRecipient.nonce,
                signature: signature,
                sender_encrypted_message: encryptedForSender.encrypted_message,
                sender_encrypted_key: encryptedForSender.encrypted_key,
                sender_iv: encryptedForSender.iv
            }
        };

        console.log('\n📡 Enviando por WebSocket...');
        wsService.send(wsPayload);
        console.log('✓ Mensaje enviado');

        // Agregar el mensaje localmente para el emisor
        console.log('\n➕ Agregando mensaje localmente...');
        const newMessage = {
            id: Date.now(), // ID temporal hasta que llegue la confirmación
            sender_id: user.id,
            recipient_id: selectedUser.id,
            text: messageText,
            created_at: new Date().toISOString(),
            timestamp: new Date().toISOString()
        };
        setMessages((prev) => [...prev, newMessage]);
        console.log('✓ Mensaje agregado al chat');

        console.groupEnd();
    };

    const sendGroupMessage = async () => {
        console.group('📤 ENVIANDO MENSAJE A GRUPO');
        console.log('Grupo:', selectedGroup.name, '(ID:', selectedGroup.id, ')');
        console.log('Mensaje original:', messageText);

        // Obtener clave del grupo
        const storageKey = CONFIG.STORAGE_KEYS.GROUP_KEY_PREFIX + selectedGroup.id;
        console.log('🔍 Buscando clave con key:', storageKey);

        let groupKeyHex = localStorage.getItem(storageKey);
        console.log('🔑 Clave encontrada en localStorage:', groupKeyHex ? (groupKeyHex.substring(0, 32) + '...') : 'NO ENCONTRADA');

        // Si no está en localStorage, obtenerla del servidor
        if (!groupKeyHex) {
            console.log('📡 Obteniendo clave del grupo desde el servidor...');
            try {
                const encryptedKeyData = await API.getMyEncryptedGroupKey(selectedGroup.id);
                console.log('✓ Clave encriptada recibida del servidor');

                // Desencriptar la clave del grupo con nuestra clave privada RSA
                const decryptedKeyBuffer = await CryptoModule.decryptRSA(
                    encryptedKeyData.encrypted_group_key,
                    privateKey
                );

                // Convertir buffer a hex string
                const decoder = new TextDecoder();
                groupKeyHex = decoder.decode(decryptedKeyBuffer);

                console.log('✓ Clave del grupo descifrada:', groupKeyHex.substring(0, 32) + '...');

                // Guardar en localStorage para futuras sesiones
                localStorage.setItem(storageKey, groupKeyHex);
                console.log('✓ Clave guardada en localStorage');
            } catch (error) {
                console.error('❌ Error obteniendo/descifrando clave del grupo:', error);
                console.groupEnd();
                throw new Error('No se pudo obtener la clave del grupo');
            }
        }

        // Cifrar mensaje con la clave AES del grupo
        console.log('\n🔐 Cifrando mensaje con clave del grupo...');
        const { encrypted_message, iv } = await CryptoModule.encryptGroupMessage(
            messageText,
            groupKeyHex
        );
        console.log('✓ Mensaje cifrado:', encrypted_message.substring(0, 30) + '...');

        // Firmar mensaje
        console.log('\n✍️ Firmando mensaje...');
        const signature = await CryptoModule.signGroupMessage(
            messageText,
            privateKey
        );
        console.log('✓ Firma generada');

        // Enviar por WebSocket
        console.log('\n📡 Enviando por WebSocket...');
        wsService.sendGroupMessage(selectedGroup.id, encrypted_message, iv, signature);
        console.log('✓ Mensaje enviado al grupo');
        console.groupEnd();
    };

    const handleTyping = () => {
        if (typingTimeoutRef.current) {
            clearTimeout(typingTimeoutRef.current);
        }

        if (chatType === 'user' && selectedUser) {
            wsService.sendTyping(selectedUser.id);
        } else if (chatType === 'group' && selectedGroup) {
            wsService.sendGroupTyping(selectedGroup.id);
        }

        typingTimeoutRef.current = setTimeout(() => {
            // Typing stopped
        }, 1000);
    };

    const handleMessageChange = (e) => {
        setMessageText(e.target.value);
        handleTyping();
    };

    // Renderizar header según tipo de chat
    const renderHeader = () => {
        if (chatType === 'user' && selectedUser) {
            return (
                <>
                    <h2>{selectedUser.username}</h2>
                    <div className="chat-actions">
                        <button onClick={onBack} className="btn-back" title="Volver" />
                    </div>
                </>
            );
        } else if (chatType === 'group' && selectedGroup) {
            return (
                <>
                    <div className="group-header-info">
                        <h2>{selectedGroup.name}</h2>
                        <span className="member-count">{selectedGroup.member_count} miembros</span>
                    </div>
                    <div className="chat-actions">
                        <button onClick={onShowGroupDetails} className="btn-icon" title="Ver detalles del grupo">
                            👥
                        </button>
                        <button onClick={onBack} className="btn-back" title="Volver" />
                    </div>
                </>
            );
        }
        return null;
    };

    // Renderizar mensaje según tipo
    const renderMessage = (msg) => {
        const isMine = chatType === 'user'
            ? msg.sender_id === user.id
            : msg.isMine;

        return (
            <div key={msg.id} className={`message ${isMine ? 'sent' : 'received'}`}>
                <div className="message-content">
                    {chatType === 'group' && !isMine && (
                        <div className="message-sender">{msg.sender_username}</div>
                    )}
                    <span className="message-text">{msg.text}</span>
                    <span className="message-time">
                        {new Date(msg.created_at).toLocaleTimeString('es-ES', {
                            hour: '2-digit',
                            minute: '2-digit'
                        })}
                    </span>
                </div>
            </div>
        );
    };

    if (!activeChat) {
        return (
            <div className="chat-area empty">
                <div className="empty-state">
                    <h2>👋 ¡Bienvenido!</h2>
                    <p>
                        {chatType === 'group'
                            ? 'Selecciona un grupo para comenzar a chatear'
                            : 'Selecciona un contacto para comenzar a chatear'}
                    </p>
                </div>
            </div>
        );
    }

    return (
        <div className="chat-area">
            <div className="chat-header">
                {renderHeader()}
            </div>

            <div className="messages-container">
                {loading ? (
                    <div className="loading">Cargando mensajes...</div>
                ) : messages.length === 0 ? (
                    <div className="empty-messages">
                        <p>No hay mensajes aún. ¡Envía el primero!</p>
                    </div>
                ) : (
                    messages.map(renderMessage)
                )}
                {typingUser && (
                    <div className="message received">
                        <div className="message-content typing-bubble">
                            <div className="typing-dots">
                                <span></span>
                                <span></span>
                                <span></span>
                            </div>
                        </div>
                    </div>
                )}
                <div ref={messagesEndRef} />
            </div>

            <form className="message-input-container" onSubmit={handleSendMessage}>
                <input
                    type="text"
                    className="message-input"
                    placeholder={
                        chatType === 'group'
                            ? `Mensaje a ${selectedGroup?.name}...`
                            : `Mensaje a ${selectedUser?.username}...`
                    }
                    value={messageText}
                    onChange={handleMessageChange}
                    disabled={sending}
                />
                <button
                    type="submit"
                    className="btn-send"
                    disabled={sending || !messageText.trim()}
                    title={sending ? 'Enviando...' : 'Enviar mensaje'}
                />
            </form>
        </div>
    );
};

export default ChatArea;
