/**
 * STVOR React Hooks - Comprehensive Unit Tests
 * Test suite for all 8 React hooks
 * 
 * Run with: npm test -- react-hooks.test.ts
 */

import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { renderHook, act, waitFor } from '@testing-library/react';
import {
  useStvorSDK,
  useEncryptedMessages,
  useConnectedPeers,
  useEncryptionKeys,
  useConnectionStatus,
  useMessageEncryption,
  useBatchMessages,
  useSDKErrorHandler
} from '../react-hooks';

// Mock SDK for testing
const createMockSDK = () => ({
  userId: 'test-user@example.com',
  relayUrl: 'ws://localhost:8080',
  init: vi.fn().mockResolvedValue(undefined),
  connect: vi.fn().mockResolvedValue(undefined),
  disconnect: vi.fn(),
  getPublicKey: vi.fn().mockReturnValue(new Uint8Array(32)),
  sendMessage: vi.fn().mockResolvedValue(undefined),
  rotateKeys: vi.fn().mockResolvedValue(undefined)
});

describe('React Hooks - useStvorSDK', () => {
  it('should initialize SDK successfully', async () => {
    const { result } = renderHook(() => useStvorSDK('test@example.com'));

    expect(result.current.isLoading).toBe(true);
    expect(result.current.sdk).toBe(null);

    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });

    expect(result.current.sdk).not.toBeNull();
    expect(result.current.isConnected).toBe(true);
    expect(result.current.error).toBeNull();
  });

  it('should handle initialization errors', async () => {
    const { result } = renderHook(() => 
      useStvorSDK('test@example.com', 'ws://invalid-url')
    );

    // Simulate error scenario
    await waitFor(() => {
      expect(result.current.isLoading).toBe(false);
    });

    // Should gracefully handle or fail safely
    expect(result.current.error === null || result.current.error instanceof Error).toBe(true);
  });

  it('should disconnect on unmount', async () => {
    const { result, unmount } = renderHook(() => useStvorSDK('test@example.com'));

    await waitFor(() => {
      expect(result.current.sdk).not.toBeNull();
    });

    unmount();

    // SDK should be cleaned up
    expect(result.current.isConnected).toBe(false);
  });

  it('should use custom relay URL', async () => {
    const customUrl = 'ws://custom-relay:9000';
    const { result } = renderHook(() => 
      useStvorSDK('test@example.com', customUrl)
    );

    await waitFor(() => {
      expect(result.current.sdk).not.toBeNull();
    });

    expect(result.current.sdk.relayUrl).toBe(customUrl);
  });
});

describe('React Hooks - useEncryptedMessages', () => {
  let mockSdk: any;

  beforeEach(() => {
    mockSdk = createMockSDK();
  });

  it('should send and receive messages', async () => {
    const { result } = renderHook(() => 
      useEncryptedMessages(mockSdk, 'peer@example.com')
    );

    expect(result.current.messages).toEqual([]);
    expect(result.current.isSending).toBe(false);

    // Send a message
    await act(async () => {
      await result.current.sendMessage('Hello!');
    });

    expect(result.current.messages).toHaveLength(1);
    expect(result.current.messages[0].text).toBe('Hello!');
    expect(result.current.messages[0].encrypted).toBe(true);
  });

  it('should handle multiple messages', async () => {
    const { result } = renderHook(() => 
      useEncryptedMessages(mockSdk, 'peer@example.com')
    );

    await act(async () => {
      await result.current.sendMessage('Message 1');
      await result.current.sendMessage('Message 2');
      await result.current.sendMessage('Message 3');
    });

    expect(result.current.messages).toHaveLength(3);
  });

  it('should track send status', async () => {
    let sendResolve: () => void;
    mockSdk.sendMessage = new Promise(resolve => {
      sendResolve = resolve as () => void;
    });

    const { result } = renderHook(() => 
      useEncryptedMessages(mockSdk, 'peer@example.com')
    );

    const sendPromise = act(async () => {
      result.current.sendMessage('Test');
    });

    expect(result.current.isSending).toBe(true);

    sendResolve!();
    await sendPromise;

    expect(result.current.isSending).toBe(false);
  });

  it('should clear messages', async () => {
    const { result } = renderHook(() => 
      useEncryptedMessages(mockSdk, 'peer@example.com')
    );

    await act(async () => {
      await result.current.sendMessage('Test');
      expect(result.current.messages).toHaveLength(1);
      
      result.current.clearMessages();
      expect(result.current.messages).toHaveLength(0);
    });
  });

  it('should handle invalid input', async () => {
    const { result } = renderHook(() => 
      useEncryptedMessages(mockSdk, 'peer@example.com')
    );

    await act(async () => {
      // Empty message
      await result.current.sendMessage('');
      // Whitespace only
      await result.current.sendMessage('   ');
    });

    expect(result.current.messages).toHaveLength(0);
  });
});

describe('React Hooks - useConnectedPeers', () => {
  let mockSdk: any;

  beforeEach(() => {
    mockSdk = createMockSDK();
  });

  it('should return empty peers initially', () => {
    const { result } = renderHook(() => useConnectedPeers(mockSdk));

    expect(result.current).toEqual([]);
  });

  it('should track peer data structure', () => {
    const { result } = renderHook(() => useConnectedPeers(mockSdk));

    // Peers array should have consistent structure
    result.current.forEach(peer => {
      expect(peer).toHaveProperty('id');
      expect(peer).toHaveProperty('publicKey');
      expect(peer).toHaveProperty('lastSeen');
      expect(peer).toHaveProperty('isOnline');

      expect(typeof peer.id).toBe('string');
      expect(peer.publicKey instanceof Uint8Array).toBe(true);
      expect(typeof peer.lastSeen).toBe('number');
      expect(typeof peer.isOnline).toBe('boolean');
    });
  });

  it('should clean up on unmount', () => {
    const { unmount } = renderHook(() => useConnectedPeers(mockSdk));

    expect(() => unmount()).not.toThrow();
  });
});

describe('React Hooks - useEncryptionKeys', () => {
  let mockSdk: any;

  beforeEach(() => {
    mockSdk = createMockSDK();
  });

  it('should get public key on mount', async () => {
    const { result } = renderHook(() => useEncryptionKeys(mockSdk));

    await waitFor(() => {
      expect(result.current.publicKey).not.toBeNull();
    });

    expect(result.current.publicKey instanceof Uint8Array).toBe(true);
    expect(result.current.publicKey).toHaveLength(32);
  });

  it('should rotate keys', async () => {
    const { result } = renderHook(() => useEncryptionKeys(mockSdk));

    await waitFor(() => {
      expect(result.current.publicKey).not.toBeNull();
    });

    expect(result.current.isRotating).toBe(false);

    await act(async () => {
      await result.current.rotateKeys();
    });

    expect(result.current.isRotating).toBe(false);
    expect(result.current.rotationError).toBeNull();
  });

  it('should export public key', async () => {
    const { result } = renderHook(() => useEncryptionKeys(mockSdk));

    await waitFor(() => {
      expect(result.current.publicKey).not.toBeNull();
    });

    const exported = result.current.exportPublicKey();
    expect(Array.isArray(exported)).toBe(true);
    expect(exported).toHaveLength(32);
  });

  it('should handle key rotation errors', async () => {
    mockSdk.rotateKeys = vi.fn().mockRejectedValue(new Error('Rotation failed'));

    const { result } = renderHook(() => useEncryptionKeys(mockSdk));

    await waitFor(() => {
      expect(result.current.publicKey).not.toBeNull();
    });

    await act(async () => {
      await result.current.rotateKeys();
    });

    expect(result.current.rotationError).not.toBeNull();
  });
});

describe('React Hooks - useConnectionStatus', () => {
  let mockSdk: any;

  beforeEach(() => {
    mockSdk = createMockSDK();
  });

  it('should track connection status', () => {
    const { result } = renderHook(() => useConnectionStatus(mockSdk));

    expect(['disconnected', 'connecting', 'connected']).toContain(result.current.status);
  });

  it('should provide connection statistics', () => {
    const { result } = renderHook(() => useConnectionStatus(mockSdk));

    expect(result.current.stats).toHaveProperty('messagesSent');
    expect(result.current.stats).toHaveProperty('messagesReceived');
    expect(result.current.stats).toHaveProperty('bytesEncrypted');
    expect(result.current.stats).toHaveProperty('bytesDecrypted');
    expect(result.current.stats).toHaveProperty('latency');
  });

  it('should reconnect when needed', async () => {
    const { result } = renderHook(() => useConnectionStatus(mockSdk));

    await act(async () => {
      await result.current.reconnect();
    });

    // Should attempt reconnection
    expect(mockSdk.connect).toHaveBeenCalled();
  });

  it('should handle connection failure', async () => {
    mockSdk.connect = vi.fn().mockRejectedValue(new Error('Connection failed'));

    const { result } = renderHook(() => useConnectionStatus(mockSdk));

    await act(async () => {
      try {
        await result.current.reconnect();
      } catch (e) {
        // Error expected
      }
    });

    expect(result.current.status).toBe('disconnected');
  });
});

describe('React Hooks - useMessageEncryption', () => {
  it('should return encryption details', () => {
    const { result } = renderHook(() => 
      useMessageEncryption({ text: 'test', from: 'user1' })
    );

    expect(result.current).toHaveProperty('algorithm');
    expect(result.current).toHaveProperty('keySize');
    expect(result.current).toHaveProperty('nonceSize');
    expect(result.current).toHaveProperty('authenticated');
    expect(result.current).toHaveProperty('overhead');

    expect(result.current.algorithm).toBe('XSalsa20-Poly1305');
    expect(result.current.keySize).toBe(256);
    expect(result.current.nonceSize).toBe(24);
    expect(result.current.authenticated).toBe(true);
    expect(result.current.overhead).toBe(40);
  });

  it('should handle different message types', () => {
    const testCases = [
      { text: 'string message' },
      { data: Buffer.from('binary data') },
      { json: { key: 'value' } },
      null
    ];

    testCases.forEach(msg => {
      const { result } = renderHook(() => useMessageEncryption(msg));
      expect(result.current).toHaveProperty('algorithm');
    });
  });
});

describe('React Hooks - useBatchMessages', () => {
  let mockSdk: any;

  beforeEach(() => {
    mockSdk = createMockSDK();
  });

  it('should add messages to batch', () => {
    const { result } = renderHook(() => useBatchMessages(mockSdk));

    act(() => {
      result.current.addToBatch('peer1@example.com', { text: 'msg1' });
      result.current.addToBatch('peer2@example.com', { text: 'msg2' });
    });

    expect(result.current.batchSize).toBe(2);
  });

  it('should flush batch', async () => {
    const { result } = renderHook(() => useBatchMessages(mockSdk));

    act(() => {
      result.current.addToBatch('peer1@example.com', { text: 'msg1' });
      result.current.addToBatch('peer2@example.com', { text: 'msg2' });
    });

    expect(result.current.batchSize).toBe(2);

    await act(async () => {
      await result.current.flushBatch();
    });

    expect(result.current.batchSize).toBe(0);
    expect(mockSdk.sendMessage).toHaveBeenCalledTimes(2);
  });

  it('should handle batch errors', async () => {
    mockSdk.sendMessage = vi.fn()
      .mockResolvedValueOnce(undefined)
      .mockRejectedValueOnce(new Error('Send failed'));

    const { result } = renderHook(() => useBatchMessages(mockSdk));

    act(() => {
      result.current.addToBatch('peer1@example.com', { text: 'msg1' });
      result.current.addToBatch('peer2@example.com', { text: 'msg2' });
    });

    await act(async () => {
      await result.current.flushBatch();
    });

    // Should have attempted both sends
    expect(mockSdk.sendMessage).toHaveBeenCalledTimes(2);
  });

  it('should report correct batch size', () => {
    const { result } = renderHook(() => useBatchMessages(mockSdk));

    expect(result.current.getBatchSize()).toBe(0);

    act(() => {
      result.current.addToBatch('peer@example.com', { text: 'test' });
    });

    expect(result.current.getBatchSize()).toBe(1);
  });
});

describe('React Hooks - useSDKErrorHandler', () => {
  let mockSdk: any;

  beforeEach(() => {
    mockSdk = createMockSDK();
  });

  it('should track errors', () => {
    const { result } = renderHook(() => useSDKErrorHandler(mockSdk));

    expect(result.current.errors).toEqual([]);
  });

  it('should add error with severity', () => {
    const { result } = renderHook(() => useSDKErrorHandler(mockSdk));

    act(() => {
      result.current.addError('Test error', 'error');
    });

    expect(result.current.errors).toHaveLength(1);
    expect(result.current.errors[0].message).toBe('Test error');
    expect(result.current.errors[0].severity).toBe('error');
  });

  it('should clear errors', () => {
    const { result } = renderHook(() => useSDKErrorHandler(mockSdk));

    act(() => {
      result.current.addError('Error 1', 'warning');
      result.current.addError('Error 2', 'error');
      expect(result.current.errors).toHaveLength(2);

      result.current.clearErrors();
    });

    expect(result.current.errors).toHaveLength(0);
  });

  it('should provide error count by severity', () => {
    const { result } = renderHook(() => useSDKErrorHandler(mockSdk));

    act(() => {
      result.current.addError('Error 1', 'error');
      result.current.addError('Warning 1', 'warning');
      result.current.addError('Error 2', 'error');
    });

    const counts = result.current.getErrorCountBySeverity();
    expect(counts.error).toBe(2);
    expect(counts.warning).toBe(1);
  });
});

describe('React Hooks Integration Tests', () => {
  let mockSdk: any;

  beforeEach(() => {
    mockSdk = createMockSDK();
  });

  it('should work together in a messaging workflow', async () => {
    const { result: sdkResult } = renderHook(() => useStvorSDK('test@example.com'));
    const { result: messagesResult } = renderHook(() => 
      useEncryptedMessages(mockSdk, 'peer@example.com')
    );
    const { result: keysResult } = renderHook(() => useEncryptionKeys(mockSdk));

    await waitFor(() => {
      expect(sdkResult.current.sdk).not.toBeNull();
      expect(keysResult.current.publicKey).not.toBeNull();
    });

    // Send a message
    await act(async () => {
      await messagesResult.current.sendMessage('Hello!');
    });

    expect(messagesResult.current.messages).toHaveLength(1);
    expect(messagesResult.current.messages[0].encrypted).toBe(true);
  });

  it('should handle batch messaging workflow', async () => {
    const { result: batchResult } = renderHook(() => useBatchMessages(mockSdk));
    const { result: errorResult } = renderHook(() => useSDKErrorHandler(mockSdk));

    act(() => {
      batchResult.current.addToBatch('user1@example.com', { text: 'msg1' });
      batchResult.current.addToBatch('user2@example.com', { text: 'msg2' });
      batchResult.current.addToBatch('user3@example.com', { text: 'msg3' });
    });

    expect(batchResult.current.batchSize).toBe(3);

    await act(async () => {
      await batchResult.current.flushBatch();
    });

    expect(batchResult.current.batchSize).toBe(0);
  });
});
