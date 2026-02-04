#!/usr/bin/env node
/**
 * Static file server for STVOR docs with bootstrap endpoint
 */

import http from 'http';
import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import * as crypto from 'crypto';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 3001;

// Generate a random API key
function generateApiKey() {
  return 'sk_live_' + crypto.randomBytes(24).toString('hex');
}

// Generate a random project ID
function generateProjectId() {
  return 'proj_' + crypto.randomBytes(8).toString('hex');
}

const mimeTypes = {
  '.html': 'text/html',
  '.js': 'application/javascript',
  '.css': 'text/css',
  '.json': 'application/json',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
};

const server = http.createServer((req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // Bootstrap endpoint for dev
  if (req.method === 'POST' && req.url === '/bootstrap') {
    const projectId = generateProjectId();
    const apiKey = generateApiKey();
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ 
      project_id: projectId, 
      api_key: apiKey 
    }));
    return;
  }

  // Mock /usage endpoint for dashboard
  if (req.url === '/usage') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      used: 0,
      limit: 1000,
      plan: 'free'
    }));
    return;
  }

  // Mock /limits endpoint for dashboard
  if (req.url === '/limits') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      plan: 'free',
      messages_per_month: 1000,
      messages_used: 0,
      storage_mb: 100,
      storage_used: 0
    }));
    return;
  }

  // Static files
  let filePath;
  if (req.url === '/') {
    filePath = path.join(__dirname, 'index.html');
  } else if (req.url === '/dashboard.html' || req.url.startsWith('/dashboard')) {
    filePath = path.join(__dirname, 'ui', 'dashboard.html');
  } else {
    filePath = path.join(__dirname, req.url.split('?')[0]);
  }

  const ext = path.extname(filePath);
  const contentType = mimeTypes[ext] || 'text/plain';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404);
        res.end('Not Found: ' + req.url);
      } else {
        res.writeHead(500);
        res.end('Server Error');
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    }
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 STVOR Docs: http://localhost:${PORT}/`);
  console.log(`   SDK API:    http://localhost:${PORT}/sdk-docs.html`);
  console.log(`   Bootstrap:  POST http://localhost:${PORT}/bootstrap`);
});
