import { useAuth } from './contexts/AuthContext';
import AuthPage from './components/Auth/AuthPage';
import ChatPage from './components/Chat/ChatPage';

function App() {
  const { user, loading } = useAuth();

  if (loading) {
    return (
      <div className="loading-screen">
        <i className="fas fa-spinner fa-spin"></i>
        <p>Cargando...</p>
      </div>
    );
  }

  return (
    <>
      {user ? <ChatPage /> : <AuthPage />}
    </>
  );
}

export default App;
