import { useState } from 'react';
import { useAuth } from '../../contexts/AuthContext';
import './Auth.css';

const Register = ({ onSwitchToLogin }) => {
    const { register } = useAuth();
    const [formData, setFormData] = useState({
        username: '',
        email: '',
        password: '',
        confirmPassword: ''
    });
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState('');

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    const validatePassword = (password) => {
        const errors = [];
        
        if (password.length < 12) {
            errors.push('• Al menos 12 caracteres');
        }
        if (!/[A-Z]/.test(password)) {
            errors.push('• Al menos una letra mayúscula (A-Z)');
        }
        if (!/[a-z]/.test(password)) {
            errors.push('• Al menos una letra minúscula (a-z)');
        }
        if (!/[0-9]/.test(password)) {
            errors.push('• Al menos un número (0-9)');
        }
        if (!/[^A-Za-z0-9]/.test(password)) {
            errors.push('• Al menos un símbolo especial (!@#$%^&*...)');
        }
        
        return errors.length > 0 ? errors : null;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');

        // Validar contraseñas
        if (formData.password !== formData.confirmPassword) {
            setError('Las contraseñas no coinciden');
            return;
        }

        const passwordErrors = validatePassword(formData.password);
        if (passwordErrors) {
            setError(
                <div>
                    <div style={{ marginBottom: '8px', fontWeight: 'bold' }}>
                        La contraseña no cumple con los siguientes requisitos:
                    </div>
                    {passwordErrors.map((err, idx) => (
                        <div key={idx} style={{ marginLeft: '8px' }}>{err}</div>
                    ))}
                </div>
            );
            return;
        }

        setLoading(true);

        const result = await register(
            formData.username,
            formData.email,
            formData.password
        );

        if (result.success) {
            // Registro exitoso
        } else {
            setError(result.error);
        }

        setLoading(false);
    };

    return (
        <div className="auth-form">
            <h2>Crear Cuenta</h2>
            
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
                        placeholder="Elige un nombre de usuario"
                        required
                        disabled={loading}
                    />
                </div>

                <div className="form-group">
                    <label>
                        <i className="fas fa-envelope"></i> Email
                    </label>
                    <input
                        type="email"
                        name="email"
                        value={formData.email}
                        onChange={handleChange}
                        placeholder="tu@email.com"
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
                        placeholder="Mínimo 12 caracteres"
                        required
                        disabled={loading}
                    />
                    <small>Debe contener mayúsculas, minúsculas, números y símbolos</small>
                </div>

                <div className="form-group">
                    <label>
                        <i className="fas fa-lock"></i> Confirmar Contraseña
                    </label>
                    <input
                        type="password"
                        name="confirmPassword"
                        value={formData.confirmPassword}
                        onChange={handleChange}
                        placeholder="Repite tu contraseña"
                        required
                        disabled={loading}
                    />
                </div>

                <button 
                    type="submit" 
                    className="btn btn-primary"
                    disabled={loading}
                >
                    <i className="fas fa-user-plus"></i>
                    {loading ? ' Registrando...' : ' Registrarse'}
                </button>
            </form>

            <p className="switch-form">
                ¿Ya tienes cuenta?{' '}
                <button onClick={onSwitchToLogin} className="link-button">
                    Inicia sesión aquí
                </button>
            </p>
        </div>
    );
};

export default Register;
