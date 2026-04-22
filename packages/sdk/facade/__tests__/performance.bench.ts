/**
 * STVOR SDK - Performance Benchmarks
 * Measure throughput, latency, and resource usage
 * 
 * Run with: npm run bench
 */

import { performance } from 'perf_hooks';
import { Stvor } from './facade/app';
import { CryptoSessionManager } from './facade/crypto-session';

interface BenchmarkResult {
  name: string;
  iterations: number;
  totalTime: number;
  avgTime: number;
  minTime: number;
  maxTime: number;
  throughput: number; // operations per second
  p50: number;
  p95: number;
  p99: number;
}

/**
 * Measure function execution time
 */
async function benchmark(
  name: string,
  fn: () => Promise<void>,
  iterations: number = 1000
): Promise<BenchmarkResult> {
  const times: number[] = [];
  let totalTime = 0;

  console.log(`\n📊 Benchmarking: ${name}`);
  console.log(`   Running ${iterations} iterations...`);

  // Warmup
  for (let i = 0; i < 10; i++) {
    await fn();
  }

  // Benchmark
  for (let i = 0; i < iterations; i++) {
    const start = performance.now();
    await fn();
    const end = performance.now();

    const time = end - start;
    times.push(time);
    totalTime += time;

    // Progress indicator
    if ((i + 1) % Math.floor(iterations / 10) === 0) {
      process.stdout.write('.');
    }
  }

  // Calculate statistics
  times.sort((a, b) => a - b);
  const avgTime = totalTime / iterations;
  const minTime = Math.min(...times);
  const maxTime = Math.max(...times);
  const throughput = (iterations / totalTime) * 1000; // ops per second

  // Percentiles
  const p50 = times[Math.floor(times.length * 0.5)];
  const p95 = times[Math.floor(times.length * 0.95)];
  const p99 = times[Math.floor(times.length * 0.99)];

  return {
    name,
    iterations,
    totalTime,
    avgTime,
    minTime,
    maxTime,
    throughput,
    p50,
    p95,
    p99
  };
}

/**
 * Format benchmark results
 */
function formatResult(result: BenchmarkResult): string {
  return `
  ✅ ${result.name}
     • Iterations: ${result.iterations}
     • Total: ${result.totalTime.toFixed(2)}ms
     • Average: ${result.avgTime.toFixed(3)}ms
     • Min: ${result.minTime.toFixed(3)}ms
     • Max: ${result.maxTime.toFixed(3)}ms
     • P50: ${result.p50.toFixed(3)}ms
     • P95: ${result.p95.toFixed(3)}ms
     • P99: ${result.p99.toFixed(3)}ms
     • Throughput: ${result.throughput.toFixed(0)} ops/sec
  `;
}

/**
 * BENCHMARKS
 */

async function runBenchmarks() {
  console.log('🚀 STVOR SDK Performance Benchmarks\n');
  console.log('=' .repeat(60));

  const results: BenchmarkResult[] = [];

  // ========================================
  // 1. ENCRYPTION BENCHMARKS
  // ========================================
  console.log('\n🔐 ENCRYPTION BENCHMARKS');
  console.log('-'.repeat(60));

  const app = await Stvor.init({ 
    appToken: 'sk_bench_test',
    relayUrl: 'ws://localhost:8080'
  });

  const alice = await app.connect('alice@bench.test');
  const bob = await app.connect('bob@bench.test');

  // Message encryption
  const encResult = await benchmark(
    'Message Encryption',
    async () => {
      await alice.send('bob@bench.test', 'Test message');
    },
    100
  );
  results.push(encResult);

  // Batch encryption
  const batchEncResult = await benchmark(
    'Batch Encryption (10 messages)',
    async () => {
      const messages = Array(10).fill(null).map((_, i) => ({
        to: `user${i}@bench.test`,
        message: `Message ${i}`
      }));
      // Simulate batch send
      await Promise.all(
        messages.map(m => alice.send(m.to, m.message))
      );
    },
    50
  );
  results.push(batchEncResult);

  // Key exchange
  const keyExResult = await benchmark(
    'Key Exchange (X3DH)',
    async () => {
      const newUser = await app.connect(`user_${Date.now()}@bench.test`);
      await newUser.send('alice@bench.test', 'Hello');
    },
    10
  );
  results.push(keyExResult);

  // ========================================
  // 2. MESSAGE THROUGHPUT
  // ========================================
  console.log('\n📤 MESSAGE THROUGHPUT BENCHMARKS');
  console.log('-'.repeat(60));

  let messageCount = 0;
  const throughputResult = await benchmark(
    'Message Throughput',
    async () => {
      await alice.send('bob@bench.test', `Message ${messageCount++}`);
    },
    200
  );
  results.push(throughputResult);

  // ========================================
  // 3. LATENCY BENCHMARKS
  // ========================================
  console.log('\n⏱️ LATENCY BENCHMARKS');
  console.log('-'.repeat(60));

  // Measure latency distribution
  const latencies: number[] = [];
  const latencyIterations = 100;

  console.log(`\n📊 Measuring latency distribution (${latencyIterations} messages)...`);

  for (let i = 0; i < latencyIterations; i++) {
    const start = performance.now();
    await alice.send('bob@bench.test', `Latency test ${i}`);
    const end = performance.now();
    latencies.push(end - start);

    if ((i + 1) % 10 === 0) {
      process.stdout.write('.');
    }
  }

  latencies.sort((a, b) => a - b);
  const latencyResult: BenchmarkResult = {
    name: 'Message Latency',
    iterations: latencyIterations,
    totalTime: latencies.reduce((a, b) => a + b, 0),
    avgTime: latencies.reduce((a, b) => a + b, 0) / latencies.length,
    minTime: latencies[0],
    maxTime: latencies[latencies.length - 1],
    throughput: 0,
    p50: latencies[Math.floor(latencies.length * 0.5)],
    p95: latencies[Math.floor(latencies.length * 0.95)],
    p99: latencies[Math.floor(latencies.length * 0.99)]
  };
  results.push(latencyResult);

  // ========================================
  // 4. MEMORY BENCHMARKS
  // ========================================
  console.log('\n\n💾 MEMORY BENCHMARKS');
  console.log('-'.repeat(60));

  const memBefore = process.memoryUsage();

  // Create many connections
  const connections = await Promise.all(
    Array(100).fill(null).map((_, i) => 
      app.connect(`mem_test_${i}@bench.test`)
    )
  );

  const memAfter = process.memoryUsage();

  const memoryResult: BenchmarkResult = {
    name: 'Memory per Connection',
    iterations: 100,
    totalTime: 0,
    avgTime: (memAfter.heapUsed - memBefore.heapUsed) / 100,
    minTime: 0,
    maxTime: 0,
    throughput: 0,
    p50: 0,
    p95: 0,
    p99: 0
  };
  results.push(memoryResult);

  console.log(`
  📊 Memory Usage:
     • Before: ${(memBefore.heapUsed / 1024 / 1024).toFixed(2)}MB
     • After: ${(memAfter.heapUsed / 1024 / 1024).toFixed(2)}MB
     • Increase: ${((memAfter.heapUsed - memBefore.heapUsed) / 1024 / 1024).toFixed(2)}MB
     • Per connection: ${((memAfter.heapUsed - memBefore.heapUsed) / 100 / 1024).toFixed(2)}KB
  `);

  // ========================================
  // 5. CONCURRENT CONNECTIONS
  // ========================================
  console.log('\n🔗 CONCURRENT CONNECTIONS BENCHMARK');
  console.log('-'.repeat(60));

  console.log('\nTesting concurrent connections...');

  const connectionTimes: number[] = [];
  const concurrentIterations = 50;

  for (let i = 0; i < concurrentIterations; i++) {
    const start = performance.now();

    // Create 10 connections concurrently
    await Promise.all(
      Array(10).fill(null).map((_, j) =>
        app.connect(`concurrent_${i}_${j}@bench.test`)
      )
    );

    const end = performance.now();
    connectionTimes.push(end - start);

    if ((i + 1) % 10 === 0) {
      process.stdout.write('.');
    }
  }

  const concurrentResult: BenchmarkResult = {
    name: 'Concurrent Connections (10x)',
    iterations: concurrentIterations,
    totalTime: connectionTimes.reduce((a, b) => a + b, 0),
    avgTime: connectionTimes.reduce((a, b) => a + b, 0) / connectionTimes.length,
    minTime: Math.min(...connectionTimes),
    maxTime: Math.max(...connectionTimes),
    throughput: (concurrentIterations / connectionTimes.reduce((a, b) => a + b, 0)) * 1000,
    p50: connectionTimes.sort((a, b) => a - b)[Math.floor(connectionTimes.length * 0.5)],
    p95: connectionTimes[Math.floor(connectionTimes.length * 0.95)],
    p99: connectionTimes[Math.floor(connectionTimes.length * 0.99)]
  };
  results.push(concurrentResult);

  // ========================================
  // 6. CRYPTO OPERATIONS
  // ========================================
  console.log('\n\n🔒 CRYPTO OPERATIONS BENCHMARKS');
  console.log('-'.repeat(60));

  const crypto = new CryptoSessionManager();

  // Key generation
  const keyGenResult = await benchmark(
    'Key Pair Generation',
    async () => {
      // Simulate key generation
      const seed = new Uint8Array(32);
      crypto.getRandomValues(seed);
    },
    100
  );
  results.push(keyGenResult);

  // ========================================
  // SUMMARY
  // ========================================
  console.log('\n\n' + '='.repeat(60));
  console.log('📊 BENCHMARK SUMMARY');
  console.log('='.repeat(60));

  results.forEach(result => {
    console.log(formatResult(result));
  });

  // ========================================
  // PERFORMANCE TARGETS
  // ========================================
  console.log('\n\n🎯 PERFORMANCE TARGETS ANALYSIS');
  console.log('='.repeat(60));

  const targets = {
    'Message Encryption': { target: 50, unit: 'ms' },
    'Message Latency (P95)': { target: 100, unit: 'ms' },
    'Message Throughput': { target: 1000, unit: 'ops/sec' },
    'Concurrent Connections (10x)': { target: 100, unit: 'ms' },
    'Memory per Connection': { target: 1000, unit: 'KB' }
  };

  console.log('\n✅ Performance Targets:');
  
  results.forEach(result => {
    const target = targets[result.name];
    if (target) {
      let actual = result.avgTime;
      if (result.name === 'Message Throughput') {
        actual = result.throughput;
      } else if (result.name === 'Message Latency') {
        actual = result.p95;
      } else if (result.name === 'Memory per Connection') {
        actual = result.avgTime / 1024;
      }

      const status = actual <= target.target ? '✅' : '⚠️';
      console.log(
        `   ${status} ${result.name}: ${actual.toFixed(2)}${target.unit} (target: ${target.target}${target.unit})`
      );
    }
  });

  console.log('\n' + '='.repeat(60));
  console.log('✨ Benchmark Complete\n');

  // Cleanup
  await app.shutdown?.();
}

// Run benchmarks
runBenchmarks().catch(error => {
  console.error('Benchmark failed:', error);
  process.exit(1);
});
