/**
 * STVOR Web SDK - Vanilla JavaScript Example
 * Simple HTML + JS example without any frameworks
 * 
 * Usage: Open in browser, set relay URL, and start messaging
 */

// Simple vanilla JavaScript implementation
class StvorSimpleClient {
  constructor(userId, relayUrl) {
    this.userId = userId;
    this.relayUrl = relayUrl;
    this.sdk = null;
    this.messages = [];
    this.isConnected = false;
  }

  async init() {
    try {
      // In production, would import from stvor-sdk
      // For now, using mock implementation
      this.sdk = {
        userId: this.userId,
        isConnected: () => this.isConnected,
        send: (to, data) => this.mockSend(to, data),
        onMessage: (from, handler) => this.mockOnMessage(from, handler)
      };

      this.isConnected = true;
      this.updateStatus();
      return true;
    } catch (err) {
      console.error('Init failed:', err);
      return false;
    }
  }

  async mockSend(to, data) {
    // Simulate sending
    const msg = {
      id: Date.now(),
      from: this.userId,
      to,
      content: data,
      timestamp: new Date(),
      encrypted: true
    };

    this.messages.push(msg);
    this.renderMessages();
  }

  mockOnMessage(from, handler) {
    // Mock handler
    return () => {};
  }

  addMessage(from, content) {
    const msg = {
      id: Date.now(),
      from,
      content,
      timestamp: new Date(),
      received: true
    };
    this.messages.push(msg);
    this.renderMessages();
  }

  renderMessages() {
    const container = document.getElementById('messages');
    if (!container) return;

    container.innerHTML = this.messages.map(msg => `
      <div class="message ${msg.from === this.userId ? 'sent' : 'received'}">
        <div class="message-header">
          <span class="sender">${msg.from === this.userId ? 'You' : msg.from}</span>
          <span class="time">${msg.timestamp.toLocaleTimeString()}</span>
        </div>
        <div class="message-content">
          ${typeof msg.content === 'object' ? JSON.stringify(msg.content) : msg.content}
        </div>
        ${msg.encrypted ? '<div class="encrypted-badge">🔒 Encrypted</div>' : ''}
      </div>
    `).join('');

    // Scroll to bottom
    container.scrollTop = container.scrollHeight;
  }

  updateStatus() {
    const status = document.getElementById('status');
    if (status) {
      status.innerHTML = `
        <span class="status-badge ${this.isConnected ? 'connected' : 'disconnected'}">
          ${this.isConnected ? '✓ Connected' : '✗ Disconnected'}
        </span>
        <span class="user-id">${this.userId}</span>
      `;
    }
  }
}

// Initialize when DOM is ready
let client;

document.addEventListener('DOMContentLoaded', () => {
  const relayUrl = document.getElementById('relayUrl').value || 'ws://localhost:8080';
  const userId = document.getElementById('userId').value || 'user@example.com';

  client = new StvorSimpleClient(userId, relayUrl);

  // Setup event listeners
  document.getElementById('connectBtn')?.addEventListener('click', async () => {
    const success = await client.init();
    if (success) {
      document.getElementById('connectBtn').disabled = true;
      alert('Connected!');
    }
  });

  document.getElementById('sendBtn')?.addEventListener('click', sendMessage);
  document.getElementById('messageInput')?.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') sendMessage();
  });

  document.getElementById('addContactBtn')?.addEventListener('click', addContact);
});

function sendMessage() {
  const input = document.getElementById('messageInput');
  const peerSelect = document.getElementById('peerSelect');

  if (!input?.value.trim()) {
    alert('Please enter a message');
    return;
  }

  if (!peerSelect?.value) {
    alert('Please select a peer');
    return;
  }

  if (!client?.isConnected) {
    alert('Not connected');
    return;
  }

  client.mockSend(peerSelect.value, {
    text: input.value,
    timestamp: new Date()
  });

  input.value = '';
  input.focus();
}

function addContact() {
  const email = prompt('Enter email address:');
  if (!email || !email.includes('@')) {
    alert('Please enter valid email');
    return;
  }

  const select = document.getElementById('peerSelect');
  const option = document.createElement('option');
  option.value = email;
  option.textContent = email;
  select.appendChild(option);
}
