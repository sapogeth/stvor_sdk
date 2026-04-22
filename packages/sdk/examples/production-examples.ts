/**
 * STVOR SDK Production Examples
 * Real-world scenarios and best practices
 */

// ============================================================================
// EXAMPLE 1: Basic Chat Application
// ============================================================================

import { StvorSDK } from 'stvor-sdk';

async function basicChatApp() {
  console.log('=== Basic Chat Application ===\n');

  // Initialize SDK
  const sdk = await StvorSDK.create('alice@example.com', {
    storagePath: './stvor-data',
    verbose: false
  });

  try {
    // Send a message
    await sdk.send('bob@example.com', {
      type: 'message',
      text: 'Hello Bob! How are you?',
      timestamp: new Date()
    });
    console.log('✓ Message sent to bob@example.com');

    // Set up message receiver
    sdk.onMessage('bob@example.com', (message, metadata) => {
      console.log(`\n📨 New message from ${metadata.from}:`);
      console.log(`   Text: ${message.text}`);
      console.log(`   Time: ${message.timestamp}`);
    });

    // In real app, this would run indefinitely
    // for (;;) { /* wait for messages */ }

  } finally {
    await sdk.shutdown();
  }
}

// ============================================================================
// EXAMPLE 2: Batch Message Processing
// ============================================================================

async function batchMessaging() {
  console.log('=== Batch Message Processing ===\n');

  const sdk = await StvorSDK.create('alice@example.com');

  try {
    // Create 500 messages
    const messages = Array(500).fill(0).map((_, i) => ({
      id: `msg-${i}`,
      title: `Task ${i + 1}`,
      description: `Complete task number ${i + 1}`,
      dueDate: new Date(Date.now() + (i * 86400000)), // Each day
      priority: Math.random() > 0.7 ? 'high' : 'normal',
      tags: ['work', 'urgent']
    }));

    console.log(`📤 Sending ${messages.length} messages in batch...`);

    const result = await sdk.sendBatch('task-manager@example.com', messages, {
      concurrency: 50,  // 50 parallel operations
      timeout: 30000,
      onProgress: (current, total) => {
        const percent = Math.round((current / total) * 100);
        console.log(`   Progress: ${current}/${total} (${percent}%)`);
      }
    });

    console.log(`\n✓ Batch complete:`);
    console.log(`  ✓ Successful: ${result.successCount}`);
    console.log(`  ✗ Failed: ${result.failureCount}`);
    console.log(`  ⏱ Duration: ${result.durationMs}ms`);
    console.log(`  ⚡ Throughput: ${(result.successCount / result.durationMs * 1000).toFixed(0)} msgs/sec`);

  } finally {
    await sdk.shutdown();
  }
}

// ============================================================================
// EXAMPLE 3: Monitoring & Metrics Export
// ============================================================================

async function monitoringExample() {
  console.log('=== Monitoring & Metrics Export ===\n');

  const sdk = await StvorSDK.create('alice@example.com', {
    verbose: true
  });

  try {
    // Send some test messages
    const peers = ['bob@example.com', 'charlie@example.com', 'diana@example.com'];
    
    for (let i = 0; i < 100; i++) {
      try {
        await sdk.send(peers[i % peers.length], {
          index: i,
          timestamp: new Date(),
          data: Buffer.from(`Message ${i}`)
        });
      } catch (err) {
        // Some messages might fail for testing
      }
    }

    // Get current metrics
    console.log('\n📊 Current Metrics:\n');

    const report = sdk.getAnalyticsReport();
    console.log('Performance:');
    console.log(`  Total Events: ${report.summary.totalEvents}`);
    console.log(`  Success Rate: ${report.summary.successRate.toFixed(1)}%`);
    console.log(`  Avg Latency: ${report.performance.avgDurationMs.toFixed(1)}ms`);
    console.log(`  P99 Latency: ${report.performance.p99DurationMs.toFixed(1)}ms`);

    console.log('\nThroughput:');
    console.log(`  Events/sec: ${report.throughput.eventsPerSecond.toFixed(2)}`);
    console.log(`  Bytes/sec: ${report.throughput.bytesPerSecond.toFixed(2)}`);
    console.log(`  Total Bytes: ${report.throughput.totalBytes}`);

    // Get circuit breaker status
    console.log('\n🔌 Circuit Breaker Status:');
    const cbStatus = sdk.getCircuitBreakerStatus();
    Object.entries(cbStatus).forEach(([peerId, status]) => {
      console.log(`  ${peerId}: ${status.state} (${(status.failureRate * 100).toFixed(1)}% failures)`);
    });

    // Export metrics
    console.log('\n📤 Exporting Metrics:\n');

    const { MetricsExporter } = await import('stvor-sdk');
    
    // Prometheus format
    const prometheus = MetricsExporter.createPrometheus('my-app');
    prometheus.recordMetric('messages_sent', report.summary.totalEvents);
    prometheus.recordMetric('success_rate', report.summary.successRate);
    console.log('✓ Prometheus exporter created');

    // JSON format
    const json = MetricsExporter.createJSON();
    await json.export();
    console.log('✓ JSON metrics exported');

  } finally {
    await sdk.shutdown();
  }
}

// ============================================================================
// EXAMPLE 4: Error Handling & Recovery
// ============================================================================

async function errorHandlingExample() {
  console.log('=== Error Handling & Recovery ===\n');

  const sdk = await StvorSDK.create('alice@example.com');

  try {
    // Simulate sending to multiple peers with some failures
    const peers = [
      'bob@example.com',
      'charlie@example.com',
      'diana@example.com',
      'eve@example.com'
    ];

    console.log('📤 Sending messages with automatic retry...\n');

    const results = await Promise.allSettled(
      peers.map(peer =>
        sdk.send(peer, {
          text: `Hello ${peer}`,
          timestamp: new Date()
        })
      )
    );

    // Handle results
    const successful = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;

    console.log(`✓ Results: ${successful} successful, ${failed} failed`);

    if (failed > 0) {
      console.log('\n⚠️  Some messages failed. Checking circuit breaker status...\n');

      const status = sdk.getCircuitBreakerStatus();
      const failedPeers = Object.entries(status)
        .filter(([_, s]) => s.state !== 'CLOSED')
        .map(([peer, s]) => ({ peer, ...s }));

      if (failedPeers.length > 0) {
        console.log('Failed peers:');
        failedPeers.forEach(p => {
          console.log(`  ${p.peer}: ${p.state} (will retry in ${p.nextRetryIn}ms)`);
        });

        console.log('\n🔄 Recovering failed peers...');
        failedPeers.forEach(p => {
          sdk.resetCircuitBreakerForPeer(p.peer);
          console.log(`  ✓ Reset circuit breaker for ${p.peer}`);
        });
      }
    }

  } finally {
    await sdk.shutdown();
  }
}

// ============================================================================
// EXAMPLE 5: Custom Retry Policies
// ============================================================================

async function customRetryExample() {
  console.log('=== Custom Retry Policies ===\n');

  const sdk = await StvorSDK.create('alice@example.com');

  try {
    // Use different retry strategies for different scenarios

    // Scenario 1: Critical message - aggressive retry
    console.log('1️⃣  Sending critical message with aggressive retry...');
    try {
      await sdk.send('bob@example.com', 
        { priority: 'CRITICAL', data: 'Important' },
        { retryPolicy: 'aggressive' }
      );
      console.log('   ✓ Sent with aggressive retry strategy\n');
    } catch (err) {
      console.log('   ✗ Failed after retries\n');
    }

    // Scenario 2: Non-critical message - conservative retry
    console.log('2️⃣  Sending non-critical message with conservative retry...');
    try {
      await sdk.send('charlie@example.com',
        { priority: 'LOW', data: 'Optional' },
        { retryPolicy: 'conservative' }
      );
      console.log('   ✓ Sent with conservative retry strategy\n');
    } catch (err) {
      console.log('   ✗ Failed (conservative strategy gives up faster)\n');
    }

    // Scenario 3: Fire-and-forget - no retry
    console.log('3️⃣  Sending fire-and-forget message...');
    try {
      await sdk.send('diana@example.com',
        { data: 'Fire and forget' },
        { retryPolicy: 'never' }
      );
      console.log('   ✓ Sent without retry\n');
    } catch (err) {
      console.log('   ✗ Failed immediately (no retry)\n');
    }

  } finally {
    await sdk.shutdown();
  }
}

// ============================================================================
// EXAMPLE 6: Rate Limiting
// ============================================================================

async function rateLimitingExample() {
  console.log('=== Rate Limiting ===\n');

  const sdk = await StvorSDK.create('alice@example.com', {
    rateLimiterOptions: {
      globalRateLimit: 1000,  // 1000 ops/sec
      peerRateLimit: 100,      // 100 ops/sec per peer
      enableBackpressure: true
    }
  });

  try {
    const peer = 'bob@example.com';
    let succeeded = 0;
    let rateLimited = 0;

    console.log('📤 Attempting to send 200 messages rapidly...\n');

    // Try to send 200 messages
    const startTime = Date.now();
    
    for (let i = 0; i < 200; i++) {
      try {
        // This will be rate limited if we exceed limits
        await sdk.send(peer, { id: i, data: `Message ${i}` });
        succeeded++;
      } catch (err) {
        if (err.code === 'RATE_LIMITED') {
          rateLimited++;
        }
      }
    }

    const duration = Date.now() - startTime;
    const throughput = (succeeded / duration * 1000).toFixed(1);

    console.log(`Results after ${duration}ms:`);
    console.log(`  ✓ Successful: ${succeeded}`);
    console.log(`  ⚠️  Rate limited: ${rateLimited}`);
    console.log(`  ⚡ Throughput: ${throughput} msgs/sec`);

    // Check rate limiter status
    console.log('\n📊 Rate Limiter Status:');
    const status = sdk.getRateLimitStatus();
    console.log(`  Global tokens: ${status.globalTokens}/${status.globalLimit}`);
    console.log(`  Peer ${peer}: ${status.peerStats[0].tokens}/${status.peerStats[0].limit}`);

  } finally {
    await sdk.shutdown();
  }
}

// ============================================================================
// EXAMPLE 7: Data Type Support
// ============================================================================

async function dataTypeExample() {
  console.log('=== Data Type Support ===\n');

  const sdk = await StvorSDK.create('alice@example.com');

  try {
    // Create message with all supported data types
    const complexData = {
      string: 'Hello',
      number: 42,
      boolean: true,
      null: null,
      date: new Date('2024-01-01'),
      array: [1, 2, 3, 4, 5],
      object: { nested: true, value: 123 },
      set: new Set([1, 2, 3]),
      map: new Map([['key1', 'value1'], ['key2', 'value2']]),
      buffer: Buffer.from('binary data'),
      deep: {
        level: {
          deep: {
            data: ['a', 'b', 'c']
          }
        }
      }
    };

    console.log('📤 Sending message with all data types...');
    await sdk.send('bob@example.com', complexData);
    console.log('✓ Sent successfully\n');

    console.log('📥 Types will be preserved through encryption:\n');
    
    sdk.onMessage('bob@example.com', (received, _) => {
      console.log('Received data types:');
      console.log(`  ✓ string: ${typeof received.string} = "${received.string}"`);
      console.log(`  ✓ number: ${typeof received.number} = ${received.number}`);
      console.log(`  ✓ boolean: ${typeof received.boolean} = ${received.boolean}`);
      console.log(`  ✓ null: ${received.null}`);
      console.log(`  ✓ date: ${received.date instanceof Date ? 'Date' : 'unknown'}`);
      console.log(`  ✓ array: ${Array.isArray(received.array) ? 'Array' : 'unknown'}`);
      console.log(`  ✓ object: ${typeof received.object} = ${JSON.stringify(received.object)}`);
      console.log(`  ✓ set: ${received.set instanceof Set ? 'Set' : 'unknown'}`);
      console.log(`  ✓ map: ${received.map instanceof Map ? 'Map' : 'unknown'}`);
      console.log(`  ✓ buffer: ${Buffer.isBuffer(received.buffer) ? 'Buffer' : 'unknown'}`);
    });

  } finally {
    await sdk.shutdown();
  }
}

// ============================================================================
// EXAMPLE 8: Production-Grade Server Setup
// ============================================================================

async function productionServerSetup() {
  console.log('=== Production-Grade Server Setup ===\n');

  // In production, you'd typically:
  // 1. Initialize SDK on app startup
  // 2. Register message handlers
  // 3. Setup monitoring
  // 4. Handle graceful shutdown

  let sdk: typeof StvorSDK.prototype;

  try {
    // Initialize
    console.log('🚀 Starting STVOR SDK...');
    sdk = await StvorSDK.create('server@myapp.com', {
      storagePath: process.env.STVOR_DATA || './stvor-data',
      verbose: process.env.NODE_ENV === 'development'
    });
    console.log('✓ SDK initialized\n');

    // Register handlers
    console.log('📨 Registering message handlers...');
    sdk.onMessage('client@example.com', (msg, meta) => {
      console.log(`Received: ${JSON.stringify(msg)}`);
    });
    console.log('✓ Handlers registered\n');

    // Setup monitoring
    console.log('📊 Setting up monitoring...');
    setInterval(() => {
      const stats = sdk.getStats();
      const report = sdk.getAnalyticsReport();
      
      console.log(`[${new Date().toISOString()}] Health check:`);
      console.log(`  Memory: ${(stats.memoryUsedMb).toFixed(1)}MB`);
      console.log(`  Success Rate: ${report.summary.successRate.toFixed(1)}%`);
      console.log(`  Active Peers: ${Object.keys(sdk.getCircuitBreakerStatus()).length}`);
    }, 60000); // Every minute

    // Graceful shutdown
    process.on('SIGTERM', async () => {
      console.log('\n📋 Received SIGTERM, shutting down gracefully...');
      
      // Finish pending operations
      const report = sdk.getAnalyticsReport();
      console.log(`Final stats: ${report.summary.totalEvents} events processed`);
      
      await sdk.shutdown();
      console.log('✓ SDK shutdown complete');
      process.exit(0);
    });

    console.log('✓ Server ready for messages (running indefinitely)\n');
    // In real app: for (;;) { await new Promise(r => setTimeout(r, 1000)); }

  } catch (err) {
    console.error('Fatal error:', err);
    if (sdk) await sdk.shutdown();
    process.exit(1);
  }
}

// ============================================================================
// Run examples
// ============================================================================

async function main() {
  const example = process.argv[2] || 'all';

  try {
    if (['all', '1'].includes(example)) await basicChatApp();
    if (['all', '2'].includes(example)) await batchMessaging();
    if (['all', '3'].includes(example)) await monitoringExample();
    if (['all', '4'].includes(example)) await errorHandlingExample();
    if (['all', '5'].includes(example)) await customRetryExample();
    if (['all', '6'].includes(example)) await rateLimitingExample();
    if (['all', '7'].includes(example)) await dataTypeExample();
    if (['all', '8'].includes(example)) await productionServerSetup();
  } catch (err) {
    console.error('Error:', err);
    process.exit(1);
  }
}

main();
