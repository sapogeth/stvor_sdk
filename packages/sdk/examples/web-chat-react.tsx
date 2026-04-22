/**
 * STVOR React Chat App Example
 * Complete web application with E2E encryption
 * 
 * Run with: npm run example:web-chat
 */

import React, { useState, useEffect, useRef } from 'react';
import {
  StvorProvider,
  useStvor,
  useMessages,
  Chat,
  StvorStatus,
  MessageInput,
  StvorErrorBoundary
} from './react-hooks';

/**
 * Chat Application Component
 */

const ChatApp: React.FC = () => {
  const { isConnected, userId } = useStvor();
  const [selectedPeer, setSelectedPeer] = useState<string>('');
  const [peers, setPeers] = useState<string[]>([
    'alice@example.com',
    'bob@example.com',
    'charlie@example.com'
  ]);

  return (
    <div style={styles.app}>
      {/* Header */}
      <div style={styles.header}>
        <div>
          <h1 style={styles.title}>🔐 Secure Chat</h1>
          <p style={styles.subtitle}>End-to-end encrypted messaging with STVOR SDK</p>
        </div>
        <StvorStatus />
      </div>

      <div style={styles.container}>
        {/* Sidebar - Peer List */}
        <div style={styles.sidebar}>
          <h3>Contacts</h3>
          <div style={styles.peerList}>
            {peers.map(peer => (
              <div
                key={peer}
                style={{
                  ...styles.peerItem,
                  background: selectedPeer === peer ? '#667eea' : '#f3f4f6',
                  color: selectedPeer === peer ? '#fff' : '#333'
                }}
                onClick={() => setSelectedPeer(peer)}
              >
                <span>👤</span>
                <div>
                  <div style={styles.peerName}>{peer.split('@')[0]}</div>
                  <div style={styles.peerEmail}>{peer}</div>
                </div>
              </div>
            ))}
          </div>

          <h3 style={{ marginTop: '24px' }}>Add Contact</h3>
          <AddContactForm
            onAdd={(email) => setPeers([...peers, email])}
          />
        </div>

        {/* Main Chat Area */}
        <div style={styles.mainArea}>
          {selectedPeer ? (
            <ChatWindow peerId={selectedPeer} />
          ) : (
            <div style={styles.welcomeMessage}>
              <h2>👋 Welcome to Secure Chat</h2>
              <p>Select a contact to start messaging</p>
              <ul>
                <li>✅ All messages are end-to-end encrypted</li>
                <li>✅ Only you and the recipient can read them</li>
                <li>✅ Messages are stored locally in IndexedDB</li>
                <li>✅ Perfect forward secrecy protection</li>
              </ul>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

/**
 * Chat Window Component
 */

interface ChatWindowProps {
  peerId: string;
}

const ChatWindow: React.FC<ChatWindowProps> = ({ peerId }) => {
  const { send } = useStvor();
  const { messages } = useMessages(peerId);
  const [myMessages, setMyMessages] = useState<any[]>([]);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const handleSendMessage = async (text: string) => {
    const msg = {
      id: `sent-${Date.now()}`,
      from: 'You',
      content: { text, timestamp: new Date() },
      timestamp: new Date(),
      read: true,
      sent: true
    };
    setMyMessages(prev => [...prev, msg]);
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  // Combine sent and received messages
  const allMessages = [
    ...myMessages,
    ...messages.map(m => ({ ...m, sent: false }))
  ].sort((a, b) => a.timestamp.getTime() - b.timestamp.getTime());

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [allMessages]);

  return (
    <div style={styles.chatWindow}>
      <div style={styles.chatWindowHeader}>
        <h2>💬 {peerId}</h2>
        <div style={styles.chatWindowStatus}>
          <span style={styles.encryptionBadge}>🔒 End-to-End Encrypted</span>
        </div>
      </div>

      <div style={styles.messagesList}>
        {allMessages.length === 0 ? (
          <div style={styles.emptyState}>
            <p>No messages yet</p>
            <p style={{ fontSize: '12px', color: '#999' }}>Send a message to start chatting</p>
          </div>
        ) : (
          allMessages.map((msg) => (
            <div
              key={msg.id}
              style={{
                ...styles.messageRow,
                justifyContent: msg.sent ? 'flex-end' : 'flex-start'
              }}
            >
              <div
                style={{
                  ...styles.messageBubble,
                  background: msg.sent ? '#667eea' : '#e5e7eb',
                  color: msg.sent ? '#fff' : '#333'
                }}
              >
                <div style={styles.messageText}>
                  {typeof msg.content === 'object' && 'text' in msg.content
                    ? msg.content.text
                    : JSON.stringify(msg.content)}
                </div>
                <div style={styles.messageTime}>
                  {msg.timestamp.toLocaleTimeString()}
                </div>
              </div>
            </div>
          ))
        )}
        <div ref={messagesEndRef} />
      </div>

      <div style={styles.messageInputWrapper}>
        <MessageInput
          peerId={peerId}
          onSend={async (data) => {
            if (typeof data === 'object' && 'text' in data) {
              await handleSendMessage(data.text as string);
            }
          }}
        />
      </div>
    </div>
  );
};

/**
 * Add Contact Form
 */

interface AddContactFormProps {
  onAdd: (email: string) => void;
}

const AddContactForm: React.FC<AddContactFormProps> = ({ onAdd }) => {
  const [email, setEmail] = useState('');

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (email.includes('@')) {
      onAdd(email);
      setEmail('');
    }
  };

  return (
    <form onSubmit={handleSubmit} style={styles.form}>
      <input
        type="email"
        value={email}
        onChange={(e) => setEmail(e.target.value)}
        placeholder="Enter email..."
        style={styles.formInput}
      />
      <button type="submit" style={styles.formButton} disabled={!email.includes('@')}>
        Add
      </button>
    </form>
  );
};

/**
 * App Wrapper with Provider
 */

export const WebChatApp: React.FC = () => {
  const relayUrl = process.env.REACT_APP_RELAY_URL || 'ws://localhost:8080';
  const userId = process.env.REACT_APP_USER_ID || 'web-user@example.com';

  return (
    <StvorErrorBoundary>
      <StvorProvider userId={userId} relayUrl={relayUrl}>
        <ChatApp />
      </StvorProvider>
    </StvorErrorBoundary>
  );
};

/**
 * Styles
 */

const styles: Record<string, React.CSSProperties> = {
  app: {
    display: 'flex',
    flexDirection: 'column',
    height: '100vh',
    backgroundColor: '#f9fafb',
    fontFamily: 'system-ui, -apple-system, sans-serif'
  },
  header: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '20px',
    backgroundColor: '#fff',
    borderBottom: '1px solid #e5e7eb',
    boxShadow: '0 1px 3px rgba(0,0,0,0.1)'
  },
  title: {
    margin: '0',
    fontSize: '24px',
    fontWeight: '700',
    color: '#667eea'
  },
  subtitle: {
    margin: '4px 0 0 0',
    fontSize: '14px',
    color: '#999'
  },
  container: {
    display: 'flex',
    flex: 1,
    overflow: 'hidden'
  },
  sidebar: {
    width: '280px',
    padding: '20px',
    backgroundColor: '#fff',
    borderRight: '1px solid #e5e7eb',
    overflowY: 'auto',
    fontSize: '14px'
  },
  peerList: {
    display: 'flex',
    flexDirection: 'column',
    gap: '8px'
  },
  peerItem: {
    display: 'flex',
    gap: '12px',
    padding: '12px',
    borderRadius: '8px',
    cursor: 'pointer',
    transition: 'all 0.2s',
    fontSize: '13px'
  },
  peerName: {
    fontWeight: 'bold',
    marginBottom: '2px'
  },
  peerEmail: {
    fontSize: '11px',
    opacity: 0.7
  },
  mainArea: {
    flex: 1,
    display: 'flex',
    flexDirection: 'column',
    overflow: 'hidden'
  },
  welcomeMessage: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    flex: 1,
    padding: '40px',
    textAlign: 'center',
    color: '#666'
  },
  chatWindow: {
    display: 'flex',
    flexDirection: 'column',
    height: '100%'
  },
  chatWindowHeader: {
    display: 'flex',
    justifyContent: 'space-between',
    alignItems: 'center',
    padding: '20px',
    backgroundColor: '#fff',
    borderBottom: '1px solid #e5e7eb'
  },
  chatWindowStatus: {
    display: 'flex',
    gap: '12px'
  },
  encryptionBadge: {
    padding: '6px 12px',
    backgroundColor: '#d1fae5',
    color: '#065f46',
    borderRadius: '12px',
    fontSize: '12px',
    fontWeight: 'bold'
  },
  messagesList: {
    flex: 1,
    overflowY: 'auto',
    padding: '20px',
    display: 'flex',
    flexDirection: 'column',
    gap: '12px'
  },
  emptyState: {
    display: 'flex',
    flexDirection: 'column',
    alignItems: 'center',
    justifyContent: 'center',
    flex: 1,
    color: '#999'
  },
  messageRow: {
    display: 'flex',
    marginBottom: '8px'
  },
  messageBubble: {
    maxWidth: '70%',
    padding: '12px 16px',
    borderRadius: '12px'
  },
  messageText: {
    marginBottom: '4px',
    wordBreak: 'break-word'
  },
  messageTime: {
    fontSize: '11px',
    opacity: 0.7
  },
  messageInputWrapper: {
    padding: '20px',
    backgroundColor: '#fff',
    borderTop: '1px solid #e5e7eb'
  },
  form: {
    display: 'flex',
    gap: '8px'
  },
  formInput: {
    flex: 1,
    padding: '10px 12px',
    border: '1px solid #d1d5db',
    borderRadius: '6px',
    fontSize: '14px',
    fontFamily: 'inherit'
  },
  formButton: {
    padding: '10px 20px',
    backgroundColor: '#667eea',
    color: '#fff',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    fontWeight: 'bold'
  }
};

export default WebChatApp;
