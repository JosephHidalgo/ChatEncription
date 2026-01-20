import './Modal.css';

const EncryptionInfoModal = ({ onClose }) => {
    return (
        <div className="modal" onClick={onClose}>
            <div className="modal-content" onClick={(e) => e.stopPropagation()}>
                <div className="modal-header">
                    <h2><i className="fas fa-shield-alt"></i> Información de Cifrado</h2>
                    <button className="modal-close" onClick={onClose}>
                        &times;
                    </button>
                </div>

                <div className="modal-body">
                    <div className="encryption-details">
                        <h3>🔐 Sistema de Cifrado Híbrido</h3>
                        <ul>
                            <li><strong>RSA-2048:</strong> Cifrado asimétrico para intercambio de claves</li>
                            <li><strong>AES-256-CBC:</strong> Cifrado simétrico para mensajes</li>
                            <li><strong>RSA-PSS:</strong> Firmas digitales para autenticidad</li>
                            <li><strong>SHA-256:</strong> Función hash para firmas</li>
                        </ul>

                        <h3>🛡️ Características de Seguridad</h3>
                        <ul>
                            <li>✅ Cifrado End-to-End (E2EE)</li>
                            <li>✅ Forward Secrecy</li>
                            <li>✅ Verificación de integridad</li>
                            <li>✅ No repudio con firmas digitales</li>
                            <li>✅ Protección contra replay attacks</li>
                        </ul>

                        <h3>🔑 Funcionamiento</h3>
                        <ol>
                            <li>Cada usuario tiene un par de claves RSA (pública/privada)</li>
                            <li>Para cada mensaje, se genera una clave AES-256 única</li>
                            <li>El mensaje se cifra con AES-256-CBC</li>
                            <li>La clave AES se cifra con la clave pública RSA del destinatario</li>
                            <li>Solo el destinatario puede descifrar con su clave privada</li>
                        </ol>
                    </div>
                </div>
            </div>
        </div>
    );
};

export default EncryptionInfoModal;
