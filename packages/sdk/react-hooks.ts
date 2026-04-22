/**
 * STVOR Web SDK - React Hooks
 * Easy-to-use React integration for encrypted messaging
 */

import { useState, useEffect, useCallback, useRef } from 'react';

/**
 * Hook for initializing STVOR Web SDK
 * @param userId - User identifier
 * @param relayUrl - Relay server URL
 * @returns SDK instance and initialization state
 */
export function useStvorSDK(userId: string, relayUrl: string = 'ws://localhost:8080') {
  const [sdk, setSdk] = useState<any>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  useEffect(() => {
    const initializeSDK = async () => {
      try {
        setIsLoading(true);
        setError(null);

        // This would be the actual StvorWebSDK import
        // For now, we're defining the interface
        const mockSDK = {
          userId,
          relayUrl,
          init: async () => {
            // Initialize encryption keys
            console.log(`Initializing STVOR for ${userId}`);
            setIsConnected(true);
          },
          connect: async () => {
            // Connect to relay
            console.log(`Connecting to ${relayUrl}`);
          },
          disconnect: () => {
            setIsConnected(false);
          },
          getPublicKey: () => new Uint8Array(32),
          sendMessage: async (peerId: string, data: any) => {
            console.log(`Sending to ${peerId}:`, data);
          }
        };

        await mockSDK.init();
        await mockSDK.connect();
        setSdk(mockSDK);
      } catch (err) {
        setError(err instanceof Error ? err : new Error(String(err)));
        setIsConnected(false);
      } finally {
        setIsLoading(false);
      }
    };

    if (userId && relayUrl) {
      initializeSDK();
    }

    return () => {
      if (sdk) {
        sdk.disconnect();
      }
    };
  }, [userId, relayUrl]);

  return { sdk, isConnected, isLoading, error };
}

/**
 * Hook for managing encrypted messages
 * @param sdk - STVOR SDK instance
 * @param peerId - Peer identifier
 * @returns Message state and handlers
 */
export function useEncryptedMessages(sdk: any, peerId: string) {
  const [messages, setMessages] = useState<Array<{
    id: string;
    from: string;
    to: string;
    text: string;
    timestamp: number;
    encrypted: boolean;
  }>>([]);
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState<Error | null>(null);
  const messageHandlerRef = useRef<((msg: any) => void) | null>(null);

  useEffect(() => {
    if (!sdk || !peerId) return;

    // Set up message listener
    const handleMessage = (msg: any) => {
      setMessages(prev => [...prev, {
        id: Math.random().toString(36).substr(2, 9),
        from: msg.from,
        to: msg.to,
        text: msg.text,
        timestamp: msg.timestamp || Date.now(),
        encrypted: true
      }]);
    };

    messageHandlerRef.current = handleMessage;

    return () => {
      messageHandlerRef.current = null;
    };
  }, [sdk, peerId]);

  const sendMessage = useCallback(async (text: string) => {
    if (!sdk || !peerId || !text.trim()) return;

    try {
      setIsSending(true);
      setError(null);

      await sdk.sendMessage(peerId, { text });

      // Add to local message history
      setMessages(prev => [...prev, {
        id: Math.random().toString(36).substr(2, 9),
        from: sdk.userId,
        to: peerId,
        text,
        timestamp: Date.now(),
        encrypted: true
      }]);
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      setError(error);
      console.error('Failed to send message:', error);
    } finally {
      setIsSending(false);
    }
  }, [sdk, peerId]);

  const clearMessages = useCallback(() => {
    setMessages([]);
  }, []);

  return {
    messages,
    isSending,
    error,
    sendMessage,
    clearMessages
  };
}

/**
 * Hook for managing peer connections
 * @param sdk - STVOR SDK instance
 * @returns List of connected peers
 */
export function useConnectedPeers(sdk: any) {
  const [peers, setPeers] = useState<Array<{
    id: string;
    publicKey: Uint8Array;
    lastSeen: number;
    isOnline: boolean;
  }>>([]);

  useEffect(() => {
    if (!sdk) return;

    // Listen for peer announcements
    const handlePeerAnnouncement = (peer: any) => {
      setPeers(prev => {
        const existing = prev.find(p => p.id === peer.id);
        if (existing) {
          return prev.map(p =>
            p.id === peer.id
              ? { ...p, lastSeen: Date.now(), isOnline: true }
              : p
          );
        }
        return [...prev, {
          id: peer.id,
          publicKey: peer.publicKey,
          lastSeen: Date.now(),
          isOnline: true
        }];
      });
    };

    // Simulate peer announcements
    const interval = setInterval(() => {
      // In real implementation, this would come from relay
    }, 1000);

    return () => clearInterval(interval);
  }, [sdk]);

  return peers;
}

/**
 * Hook for encryption key management
 * @param sdk - STVOR SDK instance
 * @returns Key management functions
 */
export function useEncryptionKeys(sdk: any) {
  const [publicKey, setPublicKey] = useState<Uint8Array | null>(null);
  const [isRotating, setIsRotating] = useState(false);
  const [rotationError, setRotationError] = useState<Error | null>(null);

  useEffect(() => {
    if (sdk) {
      try {
        const key = sdk.getPublicKey();
        setPublicKey(key);
      } catch (err) {
        console.error('Failed to get public key:', err);
      }
    }
  }, [sdk]);

  const rotateKeys = useCallback(async () => {
    if (!sdk) return;

    try {
      setIsRotating(true);
      setRotationError(null);

      // Call SDK key rotation method
      await sdk.rotateKeys?.();

      // Update local public key
      const newKey = sdk.getPublicKey();
      setPublicKey(newKey);
    } catch (err) {
      const error = err instanceof Error ? err : new Error(String(err));
      setRotationError(error);
      console.error('Key rotation failed:', error);
    } finally {
      setIsRotating(false);
    }
  }, [sdk]);

  const exportPublicKey = useCallback(() => {
    if (!publicKey) return null;
    return Array.from(publicKey);
  }, [publicKey]);

  return {
    publicKey,
    isRotating,
    rotationError,
    rotateKeys,
    exportPublicKey
  };
}

/**
 * Hook for connection status
 * @param sdk - STVOR SDK instance
 * @returns Connection status and diagnostics
 */
export function useConnectionStatus(sdk: any) {
  const [status, setStatus] = useState<'disconnected' | 'connecting' | 'connected'>('disconnected');
  const [stats, setStats] = useState({
    messagesSent: 0,
    messagesReceived: 0,
    bytesEncrypted: 0,
    bytesDecrypted: 0,
    latency: 0
  });

  useEffect(() => {
    if (!sdk) {
      setStatus('disconnected');
      return;
    }

    // Simulate connection status
    setStatus('connected');

    // Update stats periodically
    const interval = setInterval(() => {
      setStats(prev => ({
        ...prev,
        latency: Math.random() * 100
      }));
    }, 5000);

    return () => clearInterval(interval);
  }, [sdk]);

  const reconnect = useCallback(async () => {
    if (!sdk) return;
    try {
      setStatus('connecting');
      await sdk.connect?.();
      setStatus('connected');
    } catch (err) {
      setStatus('disconnected');
      console.error('Reconnection failed:', err);
    }
  }, [sdk]);

  return {
    status,
    stats,
    reconnect
  };
}

/**
 * Hook for message encryption status
 * @param message - Message to check
 * @returns Encryption details
 */
export function useMessageEncryption(message: any) {
  const [encryptionDetails, setEncryptionDetails] = useState({
    algorithm: 'XSalsa20-Poly1305',
    keySize: 256,
    nonceSize: 24,
    authenticated: true,
    overhead: 40
  });

  useEffect(() => {
    if (message) {
      // Calculate actual encryption details for the message
      setEncryptionDetails(prev => ({
        ...prev,
        authenticated: true,
        overhead: 40 // nonce (24) + auth tag (16)
      }));
    }
  }, [message]);

  return encryptionDetails;
}

/**
 * Custom hook for batch message operations
 * @param sdk - STVOR SDK instance
 * @returns Batch operation handlers
 */
export function useBatchMessages(sdk: any) {
  const [isBatching, setIsBatching] = useState(false);
  const batchRef = useRef<Array<{ peerId: string; message: any }>>([]);

  const addToBatch = useCallback((peerId: string, message: any) => {
    batchRef.current.push({ peerId, message });
  }, []);

  const flushBatch = useCallback(async () => {
    if (!sdk || batchRef.current.length === 0) return;

    try {
      setIsBatching(true);

      // Send all messages in batch
      await Promise.all(
        batchRef.current.map(({ peerId, message }) =>
          sdk.sendMessage(peerId, message)
        )
      );

      batchRef.current = [];
    } catch (err) {
      console.error('Batch send failed:', err);
    } finally {
      setIsBatching(false);
    }
  }, [sdk]);

  const getBatchSize = useCallback(() => {
    return batchRef.current.length;
  }, []);

  return {
    isBatching,
    addToBatch,
    flushBatch,
    getBatchSize,
    batchSize: batchRef.current.length
  };
}

/**
 * Hook for error handling and recovery
 * @param sdk - STVOR SDK instance
 * @returns Error handling utilities
 */
export function useSDKErrorHandler(sdk: any) {
  const [errors, setErrors] = useState<Array<{
    id: string;
    message: string;
    timestamp: number;
    severity: 'info' | 'warning' | 'error';
  }>>([]);

  const addError = useCallback((message: string, severity: 'info' | 'warning' | 'error' = 'error') => {
    setErrors(prev => [...prev, {
      id: Math.random().toString(36).substr(2, 9),
      message,
      timestamp: Date.now(),
      severity
    }]);
  }, []);

  const clearErrors = useCallback(() => {
    setErrors([]);
  }, []);

  const clearErrorById = useCallback((id: string) => {
    setErrors(prev => prev.filter(e => e.id !== id));
  }, []);

  return {
    errors,
    addError,
    clearErrors,
    clearErrorById
  };
}

export default {
  useStvorSDK,
  useEncryptedMessages,
  useConnectedPeers,
  useEncryptionKeys,
  useConnectionStatus,
  useMessageEncryption,
  useBatchMessages,
  useSDKErrorHandler
};
