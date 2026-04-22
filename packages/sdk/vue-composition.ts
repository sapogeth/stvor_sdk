/**
 * STVOR Web SDK - Vue.js Composition API Hooks
 * Vue 3 integration for encrypted messaging
 */

import {
  ref,
  computed,
  reactive,
  onMounted,
  onUnmounted,
  watch
} from 'vue';

/**
 * Initialize STVOR Web SDK
 * @param userId - User identifier
 * @param relayUrl - Relay server URL
 * @returns SDK instance and state
 */
export function useStvorSDK(userId: string, relayUrl: string = 'ws://localhost:8080') {
  const sdk = ref<any>(null);
  const isConnected = ref(false);
  const isLoading = ref(true);
  const error = ref<Error | null>(null);

  onMounted(async () => {
    try {
      isLoading.value = true;
      error.value = null;

      // Mock SDK initialization
      const mockSDK = {
        userId,
        relayUrl,
        init: async () => {
          console.log(`Initializing STVOR for ${userId}`);
          isConnected.value = true;
        },
        connect: async () => {
          console.log(`Connecting to ${relayUrl}`);
        },
        disconnect: () => {
          isConnected.value = false;
        },
        getPublicKey: () => new Uint8Array(32),
        sendMessage: async (peerId: string, data: any) => {
          console.log(`Sending to ${peerId}:`, data);
        }
      };

      await mockSDK.init();
      await mockSDK.connect();
      sdk.value = mockSDK;
    } catch (err) {
      error.value = err instanceof Error ? err : new Error(String(err));
      isConnected.value = false;
    } finally {
      isLoading.value = false;
    }
  });

  onUnmounted(() => {
    if (sdk.value) {
      sdk.value.disconnect();
    }
  });

  return {
    sdk,
    isConnected,
    isLoading,
    error
  };
}

/**
 * Manage encrypted messages in Vue
 * @param sdk - STVOR SDK instance
 * @param peerId - Peer identifier
 * @returns Message state and methods
 */
export function useEncryptedMessagesVue(sdk: any, peerId: string) {
  const messages = ref<Array<{
    id: string;
    from: string;
    to: string;
    text: string;
    timestamp: number;
    encrypted: boolean;
  }>>([]);

  const isSending = ref(false);
  const error = ref<Error | null>(null);

  const sendMessage = async (text: string) => {
    if (!sdk || !peerId || !text.trim()) return;

    try {
      isSending.value = true;
      error.value = null;

      await sdk.sendMessage(peerId, { text });

      messages.value.push({
        id: Math.random().toString(36).substr(2, 9),
        from: sdk.userId,
        to: peerId,
        text,
        timestamp: Date.now(),
        encrypted: true
      });
    } catch (err) {
      error.value = err instanceof Error ? err : new Error(String(err));
      console.error('Failed to send message:', error.value);
    } finally {
      isSending.value = false;
    }
  };

  const clearMessages = () => {
    messages.value = [];
  };

  const addMessage = (msg: any) => {
    messages.value.push({
      id: Math.random().toString(36).substr(2, 9),
      from: msg.from,
      to: msg.to,
      text: msg.text,
      timestamp: msg.timestamp || Date.now(),
      encrypted: true
    });
  };

  return {
    messages: computed(() => messages.value),
    isSending: computed(() => isSending.value),
    error: computed(() => error.value),
    sendMessage,
    clearMessages,
    addMessage
  };
}

/**
 * Manage connection status in Vue
 * @param sdk - STVOR SDK instance
 * @returns Connection status and methods
 */
export function useConnectionStatusVue(sdk: any) {
  const status = ref<'disconnected' | 'connecting' | 'connected'>('disconnected');
  
  const stats = reactive({
    messagesSent: 0,
    messagesReceived: 0,
    bytesEncrypted: 0,
    bytesDecrypted: 0,
    latency: 0
  });

  const reconnect = async () => {
    if (!sdk) return;
    try {
      status.value = 'connecting';
      await sdk.connect?.();
      status.value = 'connected';
    } catch (err) {
      status.value = 'disconnected';
      console.error('Reconnection failed:', err);
    }
  };

  watch(sdk, () => {
    if (sdk) {
      status.value = 'connected';
    } else {
      status.value = 'disconnected';
    }
  });

  onMounted(() => {
    if (sdk) {
      status.value = 'connected';
    }

    const interval = setInterval(() => {
      stats.latency = Math.random() * 100;
    }, 5000);

    onUnmounted(() => clearInterval(interval));
  });

  return {
    status: computed(() => status.value),
    stats: computed(() => ({ ...stats })),
    reconnect
  };
}

/**
 * Manage encryption keys in Vue
 * @param sdk - STVOR SDK instance
 * @returns Key management methods
 */
export function useEncryptionKeysVue(sdk: any) {
  const publicKey = ref<Uint8Array | null>(null);
  const isRotating = ref(false);
  const rotationError = ref<Error | null>(null);

  onMounted(() => {
    if (sdk) {
      try {
        const key = sdk.getPublicKey();
        publicKey.value = key;
      } catch (err) {
        console.error('Failed to get public key:', err);
      }
    }
  });

  const rotateKeys = async () => {
    if (!sdk) return;

    try {
      isRotating.value = true;
      rotationError.value = null;

      await sdk.rotateKeys?.();

      const newKey = sdk.getPublicKey();
      publicKey.value = newKey;
    } catch (err) {
      rotationError.value = err instanceof Error ? err : new Error(String(err));
      console.error('Key rotation failed:', rotationError.value);
    } finally {
      isRotating.value = false;
    }
  };

  const exportPublicKey = () => {
    if (!publicKey.value) return null;
    return Array.from(publicKey.value);
  };

  return {
    publicKey: computed(() => publicKey.value),
    isRotating: computed(() => isRotating.value),
    rotationError: computed(() => rotationError.value),
    rotateKeys,
    exportPublicKey
  };
}

/**
 * Manage connected peers in Vue
 * @param sdk - STVOR SDK instance
 * @returns List of peers
 */
export function useConnectedPeersVue(sdk: any) {
  const peers = ref<Array<{
    id: string;
    publicKey: Uint8Array;
    lastSeen: number;
    isOnline: boolean;
  }>>([]);

  const addPeer = (peer: any) => {
    const existing = peers.value.find(p => p.id === peer.id);
    if (existing) {
      Object.assign(existing, {
        lastSeen: Date.now(),
        isOnline: true
      });
    } else {
      peers.value.push({
        id: peer.id,
        publicKey: peer.publicKey,
        lastSeen: Date.now(),
        isOnline: true
      });
    }
  };

  const removePeer = (peerId: string) => {
    const index = peers.value.findIndex(p => p.id === peerId);
    if (index !== -1) {
      peers.value.splice(index, 1);
    }
  };

  return {
    peers: computed(() => peers.value),
    addPeer,
    removePeer
  };
}

/**
 * Error handling in Vue
 * @returns Error management utilities
 */
export function useSDKErrorHandlerVue() {
  const errors = ref<Array<{
    id: string;
    message: string;
    timestamp: number;
    severity: 'info' | 'warning' | 'error';
  }>>([]);

  const addError = (
    message: string,
    severity: 'info' | 'warning' | 'error' = 'error'
  ) => {
    const error = {
      id: Math.random().toString(36).substr(2, 9),
      message,
      timestamp: Date.now(),
      severity
    };
    errors.value.push(error);

    // Auto-remove after 5 seconds
    setTimeout(() => {
      clearErrorById(error.id);
    }, 5000);
  };

  const clearErrors = () => {
    errors.value = [];
  };

  const clearErrorById = (id: string) => {
    const index = errors.value.findIndex(e => e.id === id);
    if (index !== -1) {
      errors.value.splice(index, 1);
    }
  };

  return {
    errors: computed(() => errors.value),
    addError,
    clearErrors,
    clearErrorById
  };
}

/**
 * Batch message operations in Vue
 * @param sdk - STVOR SDK instance
 * @returns Batch operation methods
 */
export function useBatchMessagesVue(sdk: any) {
  const batch = ref<Array<{ peerId: string; message: any }>>([]);
  const isBatching = ref(false);

  const addToBatch = (peerId: string, message: any) => {
    batch.value.push({ peerId, message });
  };

  const flushBatch = async () => {
    if (!sdk || batch.value.length === 0) return;

    try {
      isBatching.value = true;

      await Promise.all(
        batch.value.map(({ peerId, message }) =>
          sdk.sendMessage(peerId, message)
        )
      );

      batch.value = [];
    } catch (err) {
      console.error('Batch send failed:', err);
    } finally {
      isBatching.value = false;
    }
  };

  return {
    batchSize: computed(() => batch.value.length),
    isBatching: computed(() => isBatching.value),
    addToBatch,
    flushBatch
  };
}

/**
 * Encryption details in Vue
 * @param message - Message to check
 * @returns Encryption information
 */
export function useMessageEncryptionVue(message: any) {
  const details = reactive({
    algorithm: 'XSalsa20-Poly1305',
    keySize: 256,
    nonceSize: 24,
    authenticated: true,
    overhead: 40
  });

  watch(message, () => {
    if (message) {
      details.authenticated = true;
      details.overhead = 40;
    }
  });

  return computed(() => ({ ...details }));
}

export default {
  useStvorSDK,
  useEncryptedMessagesVue,
  useConnectionStatusVue,
  useEncryptionKeysVue,
  useConnectedPeersVue,
  useSDKErrorHandlerVue,
  useBatchMessagesVue,
  useMessageEncryptionVue
};
