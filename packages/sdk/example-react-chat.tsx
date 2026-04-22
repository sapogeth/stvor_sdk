/**
 * STVOR Web SDK - React Example Component
 * Chat application using encrypted messaging
 */

import React, { useState } from 'react';
import {
  useStvorSDK,
  useEncryptedMessages,
  useConnectionStatus,
  useEncryptionKeys,
  useConnectedPeers,
  useSDKErrorHandler
} from './react-hooks';

interface StvorChatProps {
  userId: string;
  relayUrl?: string;
  onConnect?: () => void;
}

/**
 * Main encrypted chat component
 */
export function StvorChat({
  userId,
  relayUrl = 'ws://localhost:8080',
  onConnect
}: StvorChatProps) {
  const { sdk, isConnected, isLoading, error: sdkError } = useStvorSDK(userId, relayUrl);
  const { status, stats, reconnect } = useConnectionStatus(sdk);
  const { publicKey, rotateKeys, isRotating } = useEncryptionKeys(sdk);
  const { errors, addError, clearErrors, clearErrorById } = useSDKErrorHandler(sdk);
  const peers = useConnectedPeers(sdk);

  const [selectedPeerId, setSelectedPeerId] = useState<string | null>(null);
  const { messages, sendMessage, isSending } = useEncryptedMessages(sdk, selectedPeerId || '');
  const [inputValue, setInputValue] = useState('');

  const handleSendMessage = async () => {
    if (!inputValue.trim() || !selectedPeerId) return;

    try {
      await sendMessage(inputValue);
      setInputValue('');
    } catch (err) {
      addError(`Failed to send message: ${err instanceof Error ? err.message : String(err)}`, 'error');
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const handleRotateKeys = async () => {
    try {
      await rotateKeys();
      addError('Encryption keys rotated successfully', 'info');
    } catch (err) {
      addError(`Key rotation failed: ${err instanceof Error ? err.message : String(err)}`, 'error');
    }
  };

  if (isLoading) {
    return (
      <div className="stvor-chat loading">
        <div className="spinner"></div>
        <p>Initializing STVOR SDK...</p>
      </div>
    );
  }

  return (
    <div className="stvor-chat">
      {/* Header */}
      <div className="stvor-header">
        <h1>🔐 STVOR Encrypted Chat</h1>
        <div className="user-info">
          <span>User: <strong>{userId}</strong></span>
          <span className={`status ${status}`}>
            ● {status.toUpperCase()}
          </span>
        </div>
      </div>

      {/* Error Notifications */}
      {errors.length > 0 && (
        <div className="error-notifications">
          {errors.map(error => (
            <div key={error.id} className={`notification ${error.severity}`}>
              <span>{error.message}</span>
              <button
                className="close-btn"
                onClick={() => clearErrorById(error.id)}
              >
                ×
              </button>
            </div>
          ))}
        </div>
      )}

      <div className="stvor-container">
        {/* Sidebar - Peers and Stats */}
        <aside className="stvor-sidebar">
          <section className="section">
            <h3>Connected Peers</h3>
            <div className="peers-list">
              {peers.length === 0 ? (
                <p className="empty">No peers connected</p>
              ) : (
                peers.map(peer => (
                  <div
                    key={peer.id}
                    className={`peer-item ${selectedPeerId === peer.id ? 'selected' : ''}`}
                    onClick={() => setSelectedPeerId(peer.id)}
                  >
                    <span className={`indicator ${peer.isOnline ? 'online' : 'offline'}`}></span>
                    <span className="peer-name">{peer.id}</span>
                  </div>
                ))
              )}
            </div>
          </section>

          <section className="section">
            <h3>Connection Stats</h3>
            <div className="stats">
              <div className="stat-item">
                <span className="label">Latency:</span>
                <span className="value">{stats.latency.toFixed(0)}ms</span>
              </div>
              <div className="stat-item">
                <span className="label">Sent:</span>
                <span className="value">{stats.messagesSent}</span>
              </div>
              <div className="stat-item">
                <span className="label">Received:</span>
                <span className="value">{stats.messagesReceived}</span>
              </div>
              <div className="stat-item">
                <span className="label">Encrypted:</span>
                <span className="value">{(stats.bytesEncrypted / 1024).toFixed(1)}KB</span>
              </div>
            </div>
          </section>

          <section className="section">
            <h3>Security</h3>
            <div className="security-info">
              <p className="algorithm">🔒 XSalsa20-Poly1305</p>
              <p className="key-size">256-bit keys</p>
              {publicKey && (
                <p className="public-key">
                  PK: {Array.from(publicKey).slice(0, 8).map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase().slice(0, 16)}...
                </p>
              )}
              <button
                className="btn-secondary"
                onClick={handleRotateKeys}
                disabled={isRotating}
              >
                {isRotating ? 'Rotating...' : 'Rotate Keys'}
              </button>
            </div>
          </section>
        </aside>

        {/* Main Chat Area */}
        <main className="stvor-main">
          {!selectedPeerId ? (
            <div className="no-peer-selected">
              <p>Select a peer to start chatting</p>
            </div>
          ) : (
            <>
              {/* Messages */}
              <div className="messages-container">
                {messages.length === 0 ? (
                  <div className="no-messages">
                    <p>No messages yet. Start the conversation!</p>
                  </div>
                ) : (
                  messages.map(msg => (
                    <div
                      key={msg.id}
                      className={`message ${msg.from === userId ? 'sent' : 'received'}`}
                    >
                      <div className="message-header">
                        <span className="sender">{msg.from}</span>
                        <span className="time">
                          {new Date(msg.timestamp).toLocaleTimeString()}
                        </span>
                        {msg.encrypted && (
                          <span className="encrypted-badge">🔒 Encrypted</span>
                        )}
                      </div>
                      <div className="message-body">
                        {msg.text}
                      </div>
                    </div>
                  ))
                )}
              </div>

              {/* Input Area */}
              <div className="input-area">
                <textarea
                  value={inputValue}
                  onChange={(e) => setInputValue(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder="Type a message... (Enter to send, Shift+Enter for newline)"
                  disabled={isSending}
                  rows={3}
                />
                <button
                  className="btn-primary"
                  onClick={handleSendMessage}
                  disabled={isSending || !inputValue.trim()}
                >
                  {isSending ? 'Sending...' : 'Send 🔒'}
                </button>
              </div>
            </>
          )}
        </main>
      </div>

      {/* Footer */}
      <footer className="stvor-footer">
        <div className="footer-content">
          <span>STVOR Web SDK v1.0.0</span>
          <span>•</span>
          <span>Relay: {relayUrl}</span>
          <span>•</span>
          <button
            className={`btn-small ${isConnected ? 'connected' : 'disconnected'}`}
            onClick={reconnect}
            disabled={isConnected}
          >
            {isConnected ? '✓ Connected' : 'Reconnect'}
          </button>
        </div>
      </footer>

      <style jsx>{`
        .stvor-chat {
          display: flex;
          flex-direction: column;
          height: 100vh;
          background: #0d1117;
          color: #c9d1d9;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }

        .stvor-chat.loading {
          display: flex;
          justify-content: center;
          align-items: center;
          flex-direction: column;
          gap: 20px;
        }

        .spinner {
          width: 40px;
          height: 40px;
          border: 3px solid #30363d;
          border-top-color: #58a6ff;
          border-radius: 50%;
          animation: spin 1s linear infinite;
        }

        @keyframes spin {
          to { transform: rotate(360deg); }
        }

        .stvor-header {
          background: #161b22;
          border-bottom: 1px solid #30363d;
          padding: 15px 20px;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        .stvor-header h1 {
          margin: 0;
          font-size: 20px;
          color: #58a6ff;
        }

        .user-info {
          display: flex;
          gap: 20px;
          font-size: 13px;
        }

        .status {
          display: inline-flex;
          align-items: center;
          gap: 5px;
          padding: 4px 8px;
          background: #161b22;
          border-radius: 3px;
        }

        .status.connected {
          color: #3fb950;
        }

        .status.connecting {
          color: #d29922;
        }

        .status.disconnected {
          color: #f85149;
        }

        .error-notifications {
          background: #161b22;
          border-bottom: 1px solid #30363d;
          max-height: 120px;
          overflow-y: auto;
        }

        .notification {
          padding: 10px 15px;
          display: flex;
          justify-content: space-between;
          align-items: center;
          border-bottom: 1px solid #30363d;
          font-size: 13px;
        }

        .notification.error {
          background: #da3633;
          color: #ffdbdb;
        }

        .notification.warning {
          background: #d29922;
          color: #fff8c5;
        }

        .notification.info {
          background: #1f6feb;
          color: #c9d1d9;
        }

        .close-btn {
          background: none;
          border: none;
          color: inherit;
          cursor: pointer;
          font-size: 18px;
          padding: 0;
          line-height: 1;
        }

        .stvor-container {
          display: flex;
          flex: 1;
          overflow: hidden;
        }

        .stvor-sidebar {
          width: 250px;
          background: #161b22;
          border-right: 1px solid #30363d;
          overflow-y: auto;
          display: flex;
          flex-direction: column;
        }

        .section {
          padding: 15px;
          border-bottom: 1px solid #30363d;
        }

        .section h3 {
          margin: 0 0 10px 0;
          font-size: 12px;
          font-weight: 600;
          text-transform: uppercase;
          color: #8b949e;
        }

        .peers-list {
          display: flex;
          flex-direction: column;
          gap: 5px;
        }

        .peer-item {
          padding: 8px;
          background: #0d1117;
          border: 1px solid #30363d;
          border-radius: 4px;
          cursor: pointer;
          display: flex;
          align-items: center;
          gap: 8px;
          font-size: 13px;
          transition: all 0.2s;
        }

        .peer-item:hover {
          background: #1c2128;
          border-color: #444c56;
        }

        .peer-item.selected {
          background: #1f6feb;
          border-color: #388bfd;
          color: white;
        }

        .indicator {
          width: 6px;
          height: 6px;
          border-radius: 50%;
          flex-shrink: 0;
        }

        .indicator.online {
          background: #3fb950;
        }

        .indicator.offline {
          background: #8b949e;
        }

        .empty {
          color: #8b949e;
          font-size: 12px;
          text-align: center;
          padding: 10px 0;
        }

        .stats {
          display: flex;
          flex-direction: column;
          gap: 8px;
        }

        .stat-item {
          display: flex;
          justify-content: space-between;
          font-size: 12px;
        }

        .stat-item .label {
          color: #8b949e;
        }

        .stat-item .value {
          color: #79c0ff;
          font-weight: 500;
        }

        .security-info {
          display: flex;
          flex-direction: column;
          gap: 8px;
          font-size: 12px;
        }

        .algorithm {
          margin: 0;
          padding: 6px 8px;
          background: #238636;
          color: #aaffc0;
          border-radius: 3px;
        }

        .key-size {
          margin: 0;
          color: #79c0ff;
        }

        .public-key {
          margin: 0;
          color: #8b949e;
          word-break: break-all;
          font-family: monospace;
          font-size: 10px;
        }

        .stvor-main {
          flex: 1;
          display: flex;
          flex-direction: column;
          overflow: hidden;
        }

        .no-peer-selected,
        .no-messages {
          flex: 1;
          display: flex;
          justify-content: center;
          align-items: center;
          color: #8b949e;
        }

        .messages-container {
          flex: 1;
          overflow-y: auto;
          padding: 15px;
          display: flex;
          flex-direction: column;
          gap: 10px;
        }

        .message {
          max-width: 70%;
          display: flex;
          flex-direction: column;
        }

        .message.sent {
          align-self: flex-end;
          align-items: flex-end;
        }

        .message.received {
          align-self: flex-start;
          align-items: flex-start;
        }

        .message-header {
          display: flex;
          align-items: center;
          gap: 8px;
          font-size: 11px;
          color: #8b949e;
          margin-bottom: 4px;
        }

        .sender {
          font-weight: 600;
          color: #c9d1d9;
        }

        .encrypted-badge {
          background: #238636;
          color: #aaffc0;
          padding: 2px 6px;
          border-radius: 3px;
          font-size: 10px;
        }

        .message-body {
          background: #161b22;
          border: 1px solid #30363d;
          padding: 10px 12px;
          border-radius: 6px;
          word-wrap: break-word;
          font-size: 14px;
          line-height: 1.4;
        }

        .message.sent .message-body {
          background: #1f6feb;
          border-color: #388bfd;
          color: white;
        }

        .input-area {
          padding: 15px;
          background: #161b22;
          border-top: 1px solid #30363d;
          display: flex;
          gap: 10px;
        }

        textarea {
          flex: 1;
          background: #0d1117;
          border: 1px solid #30363d;
          color: #c9d1d9;
          border-radius: 6px;
          padding: 10px;
          font-family: inherit;
          font-size: 14px;
          resize: none;
          outline: none;
        }

        textarea:focus {
          border-color: #58a6ff;
          box-shadow: 0 0 0 2px rgba(88, 166, 255, 0.1);
        }

        textarea:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        button {
          border: none;
          border-radius: 6px;
          cursor: pointer;
          font-weight: 600;
          font-size: 14px;
          transition: all 0.2s;
          outline: none;
        }

        .btn-primary {
          background: #238636;
          color: white;
          padding: 10px 20px;
          border: 1px solid #2ea043;
        }

        .btn-primary:hover:not(:disabled) {
          background: #2ea043;
        }

        .btn-primary:disabled {
          background: #636e7b;
          cursor: not-allowed;
        }

        .btn-secondary {
          background: none;
          border: 1px solid #30363d;
          color: #c9d1d9;
          padding: 6px 12px;
          font-size: 12px;
          width: 100%;
        }

        .btn-secondary:hover:not(:disabled) {
          background: #1c2128;
          border-color: #444c56;
        }

        .btn-secondary:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        .btn-small {
          background: none;
          border: 1px solid #30363d;
          color: #c9d1d9;
          padding: 4px 8px;
          font-size: 12px;
        }

        .btn-small.connected {
          color: #3fb950;
          border-color: #3fb950;
        }

        .btn-small.disconnected:hover {
          background: #1c2128;
        }

        .stvor-footer {
          background: #161b22;
          border-top: 1px solid #30363d;
          padding: 10px 15px;
          font-size: 12px;
        }

        .footer-content {
          display: flex;
          justify-content: center;
          align-items: center;
          gap: 10px;
          color: #8b949e;
        }

        @media (max-width: 768px) {
          .stvor-sidebar {
            display: none;
          }

          .message {
            max-width: 90%;
          }
        }
      `}</style>
    </div>
  );
}

export default StvorChat;
