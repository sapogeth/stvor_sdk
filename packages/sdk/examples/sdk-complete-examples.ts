#!/usr/bin/env node

/**
 * STVOR SDK Examples - All Features
 * 
 * Shows:
 * 1. Basic usage (one-line initialization)
 * 2. Universal data types (strings, objects, binary, etc)
 * 3. Batch operations (10x faster)
 * 4. Resource management and graceful shutdown
 * 5. Production setup
 */

import { StvorSDK, StvorData } from '../facade/index.js';

/**
 * Example 1: Basic Usage
 */
async function example1_basic() {
  console.log('=== Example 1: Basic Usage ===\n');

  // One-line initialization
  const sdk = await StvorSDK.create('alice@example.com', {
    storagePath: './stvor-data',
    verbose: true,
  });

  console.log('✓ SDK initialized');
  console.log(`  User: ${sdk.getUserId()}`);
  console.log(`  Public Keys: ${JSON.stringify(sdk.getPublicKeys()).substring(0, 50)}...\n`);

  await sdk.shutdown();
}

/**
 * Example 2: Universal Data Types
 */
async function example2_universalData() {
  console.log('=== Example 2: Universal Data Types ===\n');

  const sdk = await StvorSDK.create('bob@example.com', { verbose: true });

  // Example peer public keys (in real app, would be exchanged via secure channel)
  const mockPeerKeys = {
    identityKey: {
      publicKey: Buffer.alloc(32, 1),
      private: Buffer.alloc(32, 2),
    },
    signedPrekey: {
      publicKey: Buffer.alloc(32, 3),
      private: Buffer.alloc(32, 4),
      signature: Buffer.alloc(64, 5),
    },
    prekeys: [
      {
        id: 1,
        publicKey: Buffer.alloc(32, 6),
        private: Buffer.alloc(32, 7),
      },
    ],
  };

  // Establish session
  await sdk.establishSession('alice@example.com', mockPeerKeys);

  // Send different data types (all automatically encrypted with type preservation)
  const examples: [string, StvorData][] = [
    ['String', 'Hello, World!'],
    ['Number', 42],
    ['Boolean', true],
    ['Object', { name: 'Alice', age: 30, email: 'alice@example.com' }],
    ['Array', [1, 2, 3, 4, 5]],
    ['Date', new Date('2025-01-15T10:30:00Z')],
    ['Binary', Buffer.from('binary data')],
    ['Map', new Map([['key1', 'value1'], ['key2', 'value2']])],
    ['Set', new Set([1, 2, 3, 4, 5])],
    ['Nested', { users: [{ id: 1, tags: new Set(['admin', 'user']) }] }],
  ];

  console.log('Sending different data types:\n');

  for (const [typeName, data] of examples) {
    try {
      // In real app: await sdk.send('alice@example.com', data);
      console.log(`  ✓ ${typeName}: ${JSON.stringify(data).substring(0, 40)}...`);
    } catch (error) {
      console.error(`  ✗ ${typeName}: ${error}`);
    }
  }

  console.log();
  await sdk.shutdown();
}

/**
 * Example 3: Batch Operations (10x faster)
 */
async function example3_batchOperations() {
  console.log('=== Example 3: Batch Operations ===\n');

  const sdk = await StvorSDK.create('charlie@example.com', { verbose: true });

  // Mock session establishment
  const mockPeerKeys = {
    identityKey: {
      publicKey: Buffer.alloc(32, 1),
      private: Buffer.alloc(32, 2),
    },
    signedPrekey: {
      publicKey: Buffer.alloc(32, 3),
      private: Buffer.alloc(32, 4),
      signature: Buffer.alloc(64, 5),
    },
    prekeys: [
      {
        id: 1,
        publicKey: Buffer.alloc(32, 6),
        private: Buffer.alloc(32, 7),
      },
    ],
  };

  await sdk.establishSession('alice@example.com', mockPeerKeys);

  // Prepare 100 messages
  const messages: StvorData[] = [];
  for (let i = 0; i < 100; i++) {
    messages.push({
      id: i,
      text: `Message ${i}`,
      timestamp: new Date(),
      data: { index: i, processed: false },
    });
  }

  console.log(`Sending ${messages.length} messages via batch API:\n`);

  try {
    const result = await sdk.sendBatch('alice@example.com', messages, {
      concurrency: 20,
      onProgress: (current, total, percent) => {
        if (current % 10 === 0) {
          console.log(`  Progress: ${percent}% (${current}/${total})`);
        }
      },
    });

    console.log(`\n✓ Batch complete:`);
    console.log(`  Success: ${result.successCount}`);
    console.log(`  Failed: ${result.failureCount}`);
    console.log(`  Time: ${result.totalTime}ms`);
    console.log(`  Throughput: ${(result.successCount / (result.totalTime / 1000)).toFixed(0)} msg/sec\n`);
  } catch (error) {
    console.error(`✗ Batch send failed: ${error}`);
  }

  await sdk.shutdown();
}

/**
 * Example 4: Message Handlers (Receiving)
 */
async function example4_messageHandlers() {
  console.log('=== Example 4: Message Handlers ===\n');

  const sdk = await StvorSDK.create('dave@example.com', { verbose: true });

  // Register handler for messages from Alice
  const unsubscribe = sdk.onMessage('alice@example.com', (data, metadata) => {
    console.log(`📨 Received from ${metadata.from} at ${metadata.timestamp.toISOString()}`);
    console.log(`   Data: ${JSON.stringify(data).substring(0, 60)}...\n`);
  });

  // In real app, would receive messages from relay server
  // and call: sdk.processMessage('alice@example.com', ciphertext, header)

  console.log('✓ Message handler registered');
  console.log('  (In real app, relay server would deliver messages here)\n');

  // Clean up
  unsubscribe();

  await sdk.shutdown();
}

/**
 * Example 5: Resource Management
 */
async function example5_resourceManagement() {
  console.log('=== Example 5: Resource Management ===\n');

  const sdk = await StvorSDK.create('eve@example.com', {
    verbose: true,
    maxCachedSessions: 100,
    sessionIdleTimeout: 5 * 60 * 1000, // 5 minutes
  });

  // Log initial stats
  console.log('Initial stats:');
  sdk.logStats();
  console.log();

  // Check health
  const healthy = sdk.isHealthy();
  console.log(`✓ Health check: ${healthy ? 'HEALTHY' : 'DEGRADED'}\n`);

  // Graceful shutdown (flushes pending operations, cleanup)
  console.log('Initiating graceful shutdown...\n');
  await sdk.shutdown();
}

/**
 * Example 6: Production Setup
 */
async function example6_productionSetup() {
  console.log('=== Example 6: Production Setup ===\n');

  // Production configuration
  const sdk = await StvorSDK.create('service@company.com', {
    storagePath: '/var/lib/stvor',
    masterPassword: process.env.STVOR_MASTER_PASSWORD || 'change-me-in-production',
    verbose: false, // Disable verbose in production
    maxCachedSessions: 10000,
    maxOTPKeys: 5000,
    sessionIdleTimeout: 24 * 60 * 60 * 1000, // 24 hours
  });

  // Setup graceful shutdown for production
  console.log('Production SDK initialized');
  console.log('Registering graceful shutdown handlers...\n');

  process.on('SIGTERM', async () => {
    console.log('SIGTERM received, shutting down gracefully...');
    await sdk.shutdown();
    process.exit(0);
  });

  process.on('SIGINT', async () => {
    console.log('SIGINT received, shutting down gracefully...');
    await sdk.shutdown();
    process.exit(0);
  });

  // Setup periodic health checks
  setInterval(() => {
    if (!sdk.isHealthy()) {
      console.error('SDK health check failed!');
      // Could trigger alerting, metrics, etc.
    }
  }, 60000); // Every minute

  // Setup periodic stats logging
  setInterval(() => {
    sdk.logStats();
  }, 5 * 60000); // Every 5 minutes

  console.log('✓ Production setup complete');
  console.log('  - Graceful shutdown handlers registered');
  console.log('  - Health checks enabled (1 min interval)');
  console.log('  - Stats logging enabled (5 min interval)\n');

  // Clean shutdown after demo
  await sdk.shutdown();
}

/**
 * Run all examples
 */
async function runAll() {
  console.log('\n╔════════════════════════════════════════╗');
  console.log('║    STVOR SDK - Complete Examples      ║');
  console.log('║    Easy E2EE Encryption for All Apps  ║');
  console.log('╚════════════════════════════════════════╝\n');

  try {
    await example1_basic();
    await new Promise((r) => setTimeout(r, 500));

    await example2_universalData();
    await new Promise((r) => setTimeout(r, 500));

    await example3_batchOperations();
    await new Promise((r) => setTimeout(r, 500));

    await example4_messageHandlers();
    await new Promise((r) => setTimeout(r, 500));

    await example5_resourceManagement();
    await new Promise((r) => setTimeout(r, 500));

    await example6_productionSetup();

    console.log('\n╔════════════════════════════════════════╗');
    console.log('║         All Examples Complete!         ║');
    console.log('╚════════════════════════════════════════╝\n');
  } catch (error) {
    console.error('Error running examples:', error);
    process.exit(1);
  }
}

// Run if executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runAll().catch(console.error);
}

export {
  example1_basic,
  example2_universalData,
  example3_batchOperations,
  example4_messageHandlers,
  example5_resourceManagement,
  example6_productionSetup,
};
