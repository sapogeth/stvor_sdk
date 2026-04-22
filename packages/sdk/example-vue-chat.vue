<template>
  <div class="stvor-vue-chat">
    <!-- Header -->
    <header class="stvor-header">
      <h1>🔐 STVOR Chat (Vue)</h1>
      <div class="header-info">
        <span class="user">{{ userId }}</span>
        <span :class="['status', status]">● {{ status.toUpperCase() }}</span>
      </div>
    </header>

    <!-- Error Notifications -->
    <Transition-group tag="div" class="notifications" name="notification">
      <div
        v-for="error in errors"
        :key="error.id"
        :class="['notification', error.severity]"
      >
        <span>{{ error.message }}</span>
        <button @click="clearErrorById(error.id)">×</button>
      </div>
    </Transition-group>

    <!-- Main Container -->
    <div v-if="isLoading" class="loading">
      <div class="spinner"></div>
      <p>Initializing SDK...</p>
    </div>

    <div v-else class="container">
      <!-- Sidebar -->
      <aside class="sidebar">
        <!-- Peers -->
        <section>
          <h3>Connected Peers</h3>
          <div class="peers-list">
            <div
              v-for="peer in peers"
              :key="peer.id"
              :class="['peer-item', { selected: selectedPeerId === peer.id }]"
              @click="selectedPeerId = peer.id"
            >
              <span :class="['indicator', peer.isOnline ? 'online' : 'offline']"></span>
              <span>{{ peer.id }}</span>
            </div>
            <p v-if="peers.length === 0" class="empty">No peers</p>
          </div>
        </section>

        <!-- Stats -->
        <section>
          <h3>Statistics</h3>
          <div class="stats">
            <div class="stat">
              <span>Latency:</span>
              <strong>{{ Math.round(stats.latency) }}ms</strong>
            </div>
            <div class="stat">
              <span>Sent:</span>
              <strong>{{ stats.messagesSent }}</strong>
            </div>
            <div class="stat">
              <span>Received:</span>
              <strong>{{ stats.messagesReceived }}</strong>
            </div>
          </div>
        </section>

        <!-- Security -->
        <section>
          <h3>Security</h3>
          <p class="algorithm">🔒 XSalsa20-Poly1305</p>
          <p class="key-size">256-bit keys</p>
          <button
            @click="rotateKeys"
            :disabled="isRotating"
            class="btn-secondary"
          >
            {{ isRotating ? 'Rotating...' : 'Rotate Keys' }}
          </button>
        </section>
      </aside>

      <!-- Main Chat -->
      <main class="main">
        <div v-if="!selectedPeerId" class="no-selection">
          <p>Select a peer to start chatting</p>
        </div>

        <template v-else>
          <!-- Messages -->
          <div class="messages">
            <div
              v-for="msg in messages"
              :key="msg.id"
              :class="['message', msg.from === userId ? 'sent' : 'received']"
            >
              <div class="msg-header">
                <span class="sender">{{ msg.from }}</span>
                <span class="time">{{ formatTime(msg.timestamp) }}</span>
                <span v-if="msg.encrypted" class="encrypted">🔒</span>
              </div>
              <div class="msg-body">{{ msg.text }}</div>
            </div>
            <div v-if="messages.length === 0" class="no-messages">
              No messages yet
            </div>
          </div>

          <!-- Input -->
          <div class="input-area">
            <textarea
              v-model="inputValue"
              @keydown.enter.ctrl="sendMessage"
              :disabled="isSending"
              placeholder="Type a message... (Ctrl+Enter to send)"
              rows="3"
            ></textarea>
            <button
              @click="sendMessage"
              :disabled="isSending || !inputValue.trim()"
              class="btn-primary"
            >
              {{ isSending ? 'Sending...' : 'Send' }}
            </button>
          </div>
        </template>
      </main>
    </div>

    <!-- Footer -->
    <footer class="footer">
      <span>STVOR Web SDK v1.0.0</span>
      <span>•</span>
      <span>{{ relayUrl }}</span>
      <button
        @click="reconnect"
        :class="['btn-footer', status]"
        :disabled="status === 'connected'"
      >
        {{ status === 'connected' ? '✓ Connected' : 'Reconnect' }}
      </button>
    </footer>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import {
  useStvorSDK,
  useEncryptedMessagesVue,
  useConnectionStatusVue,
  useEncryptionKeysVue,
  useConnectedPeersVue,
  useSDKErrorHandlerVue
} from './vue-composition';

interface Props {
  userId: string;
  relayUrl?: string;
}

const props = withDefaults(defineProps<Props>(), {
  relayUrl: 'ws://localhost:8080'
});

// Composables
const { sdk, isConnected, isLoading } = useStvorSDK(
  props.userId,
  props.relayUrl
);
const { status, stats, reconnect } = useConnectionStatusVue(sdk);
const { publicKey, rotateKeys, isRotating } = useEncryptionKeysVue(sdk);
const { peers, addPeer } = useConnectedPeersVue(sdk);
const { errors, addError, clearErrorById } = useSDKErrorHandlerVue();

// Local state
const selectedPeerId = ref<string | null>(null);
const inputValue = ref('');
const isSending = ref(false);
const messages = ref<any[]>([]);

// Computed
const userId = computed(() => props.userId);
const relayUrl = computed(() => props.relayUrl);

// Methods
const sendMessage = async () => {
  if (!inputValue.value.trim() || !selectedPeerId.value) return;

  try {
    isSending.value = true;

    // Simulate sending through SDK
    await new Promise(r => setTimeout(r, 200));

    messages.value.push({
      id: Math.random().toString(36).substr(2, 9),
      from: props.userId,
      to: selectedPeerId.value,
      text: inputValue.value,
      timestamp: Date.now(),
      encrypted: true
    });

    inputValue.value = '';
  } catch (err) {
    addError(`Failed to send: ${err}`, 'error');
  } finally {
    isSending.value = false;
  }
};

const formatTime = (timestamp: number) => {
  return new Date(timestamp).toLocaleTimeString();
};

// Initialize
onMounted(() => {
  // Simulate receiving messages
  const mockPeers = ['alice@example.com', 'bob@example.com', 'charlie@example.com'];
  mockPeers.forEach(peerId => {
    addPeer({
      id: peerId,
      publicKey: new Uint8Array(32),
      isOnline: true
    });
  });
});
</script>

<style scoped>
.stvor-vue-chat {
  display: flex;
  flex-direction: column;
  height: 100vh;
  background: #0d1117;
  color: #c9d1d9;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
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

.header-info {
  display: flex;
  gap: 15px;
  font-size: 13px;
}

.user {
  font-weight: 600;
}

.status {
  display: inline-flex;
  align-items: center;
  gap: 5px;
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

.notifications {
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

.notification button {
  background: none;
  border: none;
  color: inherit;
  cursor: pointer;
  font-size: 18px;
  padding: 0;
}

.loading {
  flex: 1;
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

.container {
  display: flex;
  flex: 1;
  overflow: hidden;
}

.sidebar {
  width: 250px;
  background: #161b22;
  border-right: 1px solid #30363d;
  overflow-y: auto;
  display: flex;
  flex-direction: column;
}

.sidebar section {
  padding: 15px;
  border-bottom: 1px solid #30363d;
}

.sidebar h3 {
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
  margin: 0;
  padding: 10px 0;
  text-align: center;
}

.stats {
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.stat {
  display: flex;
  justify-content: space-between;
  font-size: 12px;
}

.stat strong {
  color: #79c0ff;
}

.algorithm {
  margin: 0;
  padding: 6px 8px;
  background: #238636;
  color: #aaffc0;
  border-radius: 3px;
  font-size: 12px;
}

.key-size {
  margin: 5px 0;
  color: #79c0ff;
  font-size: 12px;
}

.btn-secondary {
  background: none;
  border: 1px solid #30363d;
  color: #c9d1d9;
  padding: 6px 12px;
  border-radius: 6px;
  font-size: 12px;
  cursor: pointer;
  width: 100%;
}

.btn-secondary:hover {
  background: #1c2128;
  border-color: #444c56;
}

.btn-secondary:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.main {
  flex: 1;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

.no-selection {
  flex: 1;
  display: flex;
  justify-content: center;
  align-items: center;
  color: #8b949e;
}

.messages {
  flex: 1;
  overflow-y: auto;
  padding: 15px;
  display: flex;
  flex-direction: column;
  gap: 10px;
}

.no-messages {
  text-align: center;
  color: #8b949e;
  padding: 20px;
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

.msg-header {
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

.encrypted {
  font-size: 12px;
}

.msg-body {
  background: #161b22;
  border: 1px solid #30363d;
  padding: 10px 12px;
  border-radius: 6px;
  word-wrap: break-word;
  font-size: 14px;
  line-height: 1.4;
}

.message.sent .msg-body {
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
}

textarea:focus {
  outline: none;
  border-color: #58a6ff;
  box-shadow: 0 0 0 2px rgba(88, 166, 255, 0.1);
}

textarea:disabled {
  opacity: 0.6;
}

.btn-primary {
  background: #238636;
  color: white;
  border: 1px solid #2ea043;
  border-radius: 6px;
  padding: 10px 20px;
  font-weight: 600;
  cursor: pointer;
  transition: background 0.2s;
}

.btn-primary:hover:not(:disabled) {
  background: #2ea043;
}

.btn-primary:disabled {
  background: #636e7b;
  cursor: not-allowed;
}

.footer {
  background: #161b22;
  border-top: 1px solid #30363d;
  padding: 10px 15px;
  font-size: 12px;
  display: flex;
  justify-content: center;
  align-items: center;
  gap: 10px;
  color: #8b949e;
}

.btn-footer {
  background: none;
  border: 1px solid #30363d;
  color: #c9d1d9;
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
  cursor: pointer;
}

.btn-footer.connected {
  color: #3fb950;
  border-color: #3fb950;
}

.btn-footer:hover:not(:disabled) {
  background: #1c2128;
}

.btn-footer:disabled {
  cursor: not-allowed;
}

.notification-enter-active,
.notification-leave-active {
  transition: all 0.3s ease;
}

.notification-enter-from,
.notification-leave-to {
  opacity: 0;
  transform: translateX(-10px);
}

@media (max-width: 768px) {
  .sidebar {
    display: none;
  }

  .message {
    max-width: 90%;
  }
}
</style>
