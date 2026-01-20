import { useState } from 'react';
import Login from './Login';
import Register from './Register';
import './Auth.css';

const AuthPage = () => {
    const [isLogin, setIsLogin] = useState(true);

    return (
        <div className="auth-screen">
            <div className="auth-container">
                <div className="logo">
                    <i className="fas fa-shield-alt"></i>
                    <h1>SecureChat</h1>
                    <p>Mensajería Cifrada de Extremo a Extremo</p>
                </div>

                <div className="tabs">
                    <button
                        className={`tab ${isLogin ? 'active' : ''}`}
                        onClick={() => setIsLogin(true)}
                    >
                        Iniciar Sesión
                    </button>
                    <button
                        className={`tab ${!isLogin ? 'active' : ''}`}
                        onClick={() => setIsLogin(false)}
                    >
                        Registrarse
                    </button>
                </div>

                {isLogin ? (
                    <Login onSwitchToRegister={() => setIsLogin(false)} />
                ) : (
                    <Register onSwitchToLogin={() => setIsLogin(true)} />
                )}
            </div>
        </div>
    );
};

export default AuthPage;
