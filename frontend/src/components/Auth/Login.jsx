import { useState } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import './Auth.css';

const Login = ({ onSwitchToRegister }) => {
    const { login } = useAuth();
    const [formData, setFormData] = useState({
        username: '',
        password: '',
        totpCode: ''
    });
    const [show2FA, setShow2FA] = useState(false);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setLoading(true);
        setError('');

        const result = await login(
            formData.username,
            formData.password,
            formData.totpCode || null
        );

        if (result.success) {
            // Login exitoso
        } else if (result.requires2FA) {
            setShow2FA(true);
            setError('Por favor ingresa tu código 2FA');
        } else {
            setError(result.error);
        }

        setLoading(false);
    };

    return (
        <div className="auth-form">
            <h2>Iniciar Sesión</h2>
            
            {error && <div className="error-message">{error}</div>}
            
            <form onSubmit={handleSubmit}>
                <div className="form-group">
                    <label>
                        <i className="fas fa-user"></i> Usuario
                    </label>
                    <input
                        type="text"
                        name="username"
                        value={formData.username}
                        onChange={handleChange}
                        placeholder="Ingresa tu usuario"
                        required
                        disabled={loading}
                    />
                </div>

                <div className="form-group">
                    <label>
                        <i className="fas fa-lock"></i> Contraseña
                    </label>
                    <input
                        type="password"
                        name="password"
                        value={formData.password}
                        onChange={handleChange}
                        placeholder="Ingresa tu contraseña"
                        required
                        disabled={loading}
                    />
                </div>

                {show2FA && (
                    <div className="form-group">
                        <label>
                            <i className="fas fa-key"></i> Código 2FA
                        </label>
                        <input
                            type="text"
                            name="totpCode"
                            value={formData.totpCode}
                            onChange={handleChange}
                            placeholder="123456"
                            maxLength="6"
                            disabled={loading}
                        />
                    </div>
                )}

                <button 
                    type="submit" 
                    className="btn btn-primary"
                    disabled={loading}
                >
                    <i className="fas fa-sign-in-alt"></i>
                    {loading ? ' Iniciando sesión...' : ' Iniciar Sesión'}
                </button>
            </form>

            <p className="switch-form">
                ¿No tienes cuenta?{' '}
                <button onClick={onSwitchToRegister} className="link-button">
                    Regístrate aquí
                </button>
            </p>
        </div>
    );
};

export default Login;
