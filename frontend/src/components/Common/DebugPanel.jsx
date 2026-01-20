import { useEffect, useState } from 'react';
import CONFIG from '../../utils/config';

const DebugPanel = () => {
    const [storageData, setStorageData] = useState({});

    const refreshData = () => {
        const data = {};
        Object.keys(CONFIG.STORAGE_KEYS).forEach(key => {
            const value = localStorage.getItem(CONFIG.STORAGE_KEYS[key]);
            data[CONFIG.STORAGE_KEYS[key]] = value ? 
                (value.length > 100 ? value.substring(0, 100) + '...' : value) : 
                'undefined';
        });
        setStorageData(data);
    };

    useEffect(() => {
        refreshData();
        const interval = setInterval(refreshData, 2000);
        return () => clearInterval(interval);
    }, []);

    const clearStorage = () => {
        if (confirm('¿Seguro que quieres limpiar el localStorage?')) {
            localStorage.clear();
            refreshData();
            window.location.reload();
        }
    };

    return (
        <div style={{
            position: 'fixed',
            bottom: 10,
            right: 10,
            background: 'rgba(0,0,0,0.9)',
            color: '#0f0',
            padding: '15px',
            borderRadius: '8px',
            fontSize: '11px',
            fontFamily: 'monospace',
            maxWidth: '400px',
            zIndex: 9999,
            maxHeight: '300px',
            overflow: 'auto'
        }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '10px' }}>
                <strong>🔍 Debug - localStorage</strong>
                <button 
                    onClick={clearStorage}
                    style={{
                        background: '#d63031',
                        color: 'white',
                        border: 'none',
                        padding: '2px 8px',
                        borderRadius: '4px',
                        cursor: 'pointer',
                        fontSize: '10px'
                    }}
                >
                    Clear
                </button>
            </div>
            {Object.entries(storageData).map(([key, value]) => (
                <div key={key} style={{ marginBottom: '8px', borderBottom: '1px solid #333', paddingBottom: '5px' }}>
                    <div style={{ color: '#0af' }}>{key}:</div>
                    <div style={{ 
                        color: value === 'undefined' ? '#f00' : '#0f0',
                        wordBreak: 'break-all',
                        marginLeft: '10px'
                    }}>
                        {value}
                    </div>
                </div>
            ))}
        </div>
    );
};

export default DebugPanel;
