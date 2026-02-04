/**
 * STVOR DX Facade - Relay Client
 */

import { Errors, StvorError } from './errors.js';
import * as WS from 'ws';

type JSONable = Record<string, any>;

export type RelayHandler = (msg: JSONable) => void;

interface OutgoingMessage {
  to: string;
  from: string;
  ciphertext: Uint8Array;
  nonce: Uint8Array;
}

interface IncomingMessage {
  id?: string;
  from: string;
  ciphertext: number[];
  nonce: number[];
  timestamp: string;
}

export class RelayClient {
  private relayUrl: string;
  private timeout: number;
  private appToken: string;
  private ws?: any;
  private connected: boolean = false;
  private handshakeComplete: boolean = false;
  private backoff = 1000;
  private queue: JSONable[] = [];
  private handlers: RelayHandler[] = [];
  private reconnecting = false;
  private connectPromise?: Promise<void>;
  private connectResolve?: () => void;
  private connectReject?: (err: Error) => void;
  private authFailed: boolean = false;

  constructor(relayUrl: string, appToken: string, timeout: number = 10000) {
    this.relayUrl = relayUrl.replace(/^http/, 'ws');
    this.appToken = appToken;
    this.timeout = timeout;
  }

  /**
   * Initialize the connection and wait for handshake.
   * Throws StvorError if API key is rejected.
   */
  async init(): Promise<void> {
    if (this.authFailed) {
      throw new StvorError(
        Errors.INVALID_API_KEY,
        'Relay rejected connection: invalid API key'
      );
    }
    if (this.handshakeComplete) return;
    await this.connect();
  }

  private getAuthHeaders(): Record<string, string> {
    return {
      Authorization: `Bearer ${this.appToken}`,
    };
  }

  private connect(): Promise<void> {
    if (this.connectPromise) return this.connectPromise;
    if (this.ws) return Promise.resolve();

    this.connectPromise = new Promise((resolve, reject) => {
      this.connectResolve = resolve;
      this.connectReject = reject;

      const WSClass: any = (WS as any).default ?? WS;
      this.ws = new WSClass(this.relayUrl, { headers: this.getAuthHeaders() } as any);

      // Timeout for handshake
      const handshakeTimeout = setTimeout(() => {
        if (!this.handshakeComplete) {
          this.ws?.close();
          reject(new StvorError(
            Errors.RELAY_UNAVAILABLE,
            'Relay handshake timeout'
          ));
        }
      }, this.timeout);

      this.ws.on('open', () => {
        this.connected = true;
        this.backoff = 1000;
        // Don't flush queue yet - wait for handshake
      });

      this.ws.on('message', (data: any) => {
        try {
          const json = JSON.parse(data.toString());
          
          // Handle handshake response
          if (json.type === 'handshake') {
            clearTimeout(handshakeTimeout);
            if (json.status === 'ok') {
              this.handshakeComplete = true;
              // Now flush the queue
              while (this.queue.length) {
                const m = this.queue.shift()!;
                this.doSend(m);
              }
              this.connectResolve?.();
            } else {
              // Handshake rejected
              this.authFailed = true;
              this.ws?.close();
              const err = new StvorError(
                Errors.INVALID_API_KEY,
                `Relay rejected connection: ${json.reason || 'invalid API key'}`
              );
              this.connectReject?.(err);
            }
            return;
          }
          
          // Regular message
          for (const h of this.handlers) h(json);
        } catch (e) {
          // ignore parse errors
        }
      });

      this.ws.on('close', (code: number) => {
        this.connected = false;
        this.handshakeComplete = false;
        this.ws = undefined;
        this.connectPromise = undefined;
        
        // If auth failed, don't reconnect
        if (this.authFailed) {
          return;
        }
        
        // 401/403 close codes mean auth failure
        if (code === 4001 || code === 4003) {
          this.authFailed = true;
          this.connectReject?.(new StvorError(
            Errors.INVALID_API_KEY,
            'Relay rejected connection: invalid API key'
          ));
          return;
        }
        
        this.scheduleReconnect();
      });

      this.ws.on('error', (err: any) => {
        this.connected = false;
        this.handshakeComplete = false;
        this.ws = undefined;
        this.connectPromise = undefined;
        
        if (this.authFailed) {
          return;
        }
        
        this.scheduleReconnect();
      });
    });

    return this.connectPromise;
  }

  private scheduleReconnect() {
    if (this.reconnecting) return;
    this.reconnecting = true;
    setTimeout(() => {
      this.reconnecting = false;
      this.connect();
      this.backoff = Math.min(this.backoff * 2, 30000);
    }, this.backoff);
  }

  private doSend(obj: JSONable) {
    const data = JSON.stringify(obj);
    if (this.connected && this.ws && this.handshakeComplete) {
      this.ws.send(data);
    } else {
      this.queue.push(obj);
    }
  }

  send(obj: JSONable) {
    if (this.authFailed) {
      throw new StvorError(
        Errors.INVALID_API_KEY,
        'Cannot send: relay rejected connection due to invalid API key'
      );
    }
    this.doSend(obj);
  }

  onMessage(h: RelayHandler) {
    this.handlers.push(h);
  }

  isConnected(): boolean {
    return this.connected && this.handshakeComplete;
  }

  isAuthenticated(): boolean {
    return this.handshakeComplete && !this.authFailed;
  }
}
