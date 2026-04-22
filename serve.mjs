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
  '.md': 'text/html', // Serve markdown as HTML
};

// Simple markdown to HTML converter
function markdownToHtml(markdown) {
  let html = markdown
    // Escape HTML
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  // Code blocks (``` ... ```)
  html = html.replace(/```([\s\S]*?)```/g, (match, code) => {
    return '<pre><code>' + code.trim() + '</code></pre>';
  });

  // Headers
  html = html.replace(/^### (.*?)$/gm, '<h3>$1</h3>');
  html = html.replace(/^## (.*?)$/gm, '<h2>$1</h2>');
  html = html.replace(/^# (.*?)$/gm, '<h1>$1</h1>');

  // Bold & italic
  html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');

  // Links
  html = html.replace(/\[(.*?)\]\((.*?)\)/g, '<a href="$2">$1</a>');

  // Inline code
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

  // Lists
  html = html.replace(/^\- (.*?)$/gm, '<li>$1</li>');
  html = html.replace(/(<li>.*?<\/li>)/s, '<ul>$1</ul>');

  // Tables (simple)
  html = html.replace(/^\| (.*?) \|$/gm, '<tr><td>' + 
    '$1'.split('|').map(c => '<td>' + c.trim() + '</td>').join('') + 
    '</tr>');

  // Paragraphs
  html = html.replace(/\n\n+/g, '</p><p>');
  html = '<p>' + html + '</p>';
  html = html.replace(/<p><\/p>/g, '');
  html = html.replace(/<p>(<h[1-3])/g, '$1');
  html = html.replace(/(<\/h[1-3]>)<\/p>/g, '$1');
  html = html.replace(/<p>(<pre>)/g, '$1');
  html = html.replace(/(<\/pre>)<\/p>/g, '$1');
  html = html.replace(/<p>(<ul>)/g, '$1');
  html = html.replace(/(<\/ul>)<\/p>/g, '$1');
  html = html.replace(/<p>(<table>)/g, '$1');
  html = html.replace(/(<\/table>)<\/p>/g, '$1');

  return html;
}

// HTML template wrapper
function wrapHtml(title, content) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} - STVOR</title>
  <link href="https://fonts.googleapis.com/css2?family=Courier+Prime:wght@400;700&family=Roboto+Mono:wght@400;600&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-primary: #000;
      --bg-secondary: #0a0a0a;
      --fg-primary: #fff;
      --fg-secondary: #b0b0b0;
      --accent: #0066ff;
      --border: #1a1a1a;
      --border-light: #333;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; }
    body {
      font-family: 'Courier Prime', 'SF Mono', Monaco, monospace;
      background: var(--bg-primary);
      color: var(--fg-primary);
      line-height: 1.8;
      font-size: 14px;
      letter-spacing: 0.3px;
    }
    .container {
      max-width: 1000px;
      margin: 0 auto;
      padding: 30px 20px;
    }
    .nav {
      display: flex;
      flex-wrap: wrap;
      gap: 25px;
      margin-bottom: 50px;
      padding-bottom: 25px;
      border-bottom: 1px solid var(--border-light);
    }
    .nav a {
      color: var(--fg-secondary);
      text-decoration: none;
      font-size: 13px;
      letter-spacing: 0.5px;
      transition: all 0.2s;
      position: relative;
    }
    .nav a:hover {
      color: var(--accent);
    }
    .nav a::after {
      content: '';
      position: absolute;
      bottom: -5px;
      left: 0;
      width: 0;
      height: 1px;
      background: var(--accent);
      transition: width 0.2s;
    }
    .nav a:hover::after {
      width: 100%;
    }
    h1, h2, h3, h4 {
      font-weight: 700;
      letter-spacing: -0.5px;
      margin-top: 35px;
      margin-bottom: 15px;
    }
    h1 {
      font-size: clamp(32px, 8vw, 48px);
      line-height: 1.2;
      margin-top: 0;
    }
    h2 {
      font-size: clamp(24px, 6vw, 32px);
      border-bottom: 1px solid var(--border-light);
      padding-bottom: 12px;
      margin-top: 40px;
    }
    h3 {
      font-size: clamp(18px, 4vw, 24px);
      color: var(--fg-secondary);
    }
    h4 {
      font-size: clamp(16px, 3vw, 20px);
      color: var(--fg-secondary);
    }
    p {
      margin: 15px 0;
      color: var(--fg-secondary);
      word-break: break-word;
    }
    a {
      color: var(--accent);
      text-decoration: none;
      transition: opacity 0.2s;
    }
    a:hover {
      opacity: 0.8;
      text-decoration: underline;
    }
    code {
      background: var(--border);
      border: 1px solid var(--border-light);
      border-radius: 3px;
      padding: 3px 8px;
      font-family: 'Roboto Mono', monospace;
      font-size: clamp(11px, 2vw, 13px);
      color: #ffd700;
      word-break: break-word;
    }
    pre {
      background: var(--border);
      border: 1px solid var(--border-light);
      border-radius: 4px;
      padding: clamp(12px, 3vw, 20px);
      overflow-x: auto;
      margin: 20px 0;
      font-family: 'Roboto Mono', monospace;
      font-size: clamp(10px, 2vw, 13px);
      line-height: 1.6;
      -webkit-overflow-scrolling: touch;
    }
    pre code {
      background: none;
      border: none;
      padding: 0;
      color: #ffd700;
      font-size: inherit;
    }
    ul, ol {
      margin: 15px 0;
    }
    li {
      margin: 8px 0;
      margin-left: 25px;
      color: var(--fg-secondary);
    }
    table {
      width: 100%;
      border-collapse: collapse;
      margin: 25px 0;
      overflow-x: auto;
      display: block;
    }
    th, td {
      text-align: left;
      padding: clamp(10px, 2vw, 15px);
      border-bottom: 1px solid var(--border-light);
      word-break: break-word;
    }
    th {
      background: var(--bg-secondary);
      font-weight: 700;
      color: var(--fg-secondary);
      font-size: clamp(12px, 2vw, 14px);
    }
    td {
      color: var(--fg-secondary);
      font-size: clamp(12px, 2vw, 14px);
    }
    strong {
      color: var(--fg-primary);
      font-weight: 700;
    }
    em {
      color: var(--accent);
    }
    blockquote {
      border-left: 3px solid var(--accent);
      padding-left: 20px;
      margin: 20px 0;
      color: var(--fg-secondary);
      font-style: italic;
    }
    footer {
      margin-top: 80px;
      padding-top: 25px;
      border-top: 1px solid var(--border-light);
      text-align: center;
      color: #666;
      font-size: clamp(11px, 2vw, 12px);
    }
    footer a {
      color: var(--accent);
    }
    /* Scrollbar styling */
    ::-webkit-scrollbar {
      width: 8px;
      height: 8px;
    }
    ::-webkit-scrollbar-track {
      background: var(--bg-primary);
    }
    ::-webkit-scrollbar-thumb {
      background: var(--border-light);
      border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
      background: var(--fg-secondary);
    }
    /* Mobile optimizations */
    @media (max-width: 768px) {
      .container {
        padding: 20px 15px;
      }
      .nav {
        gap: 15px;
        margin-bottom: 30px;
      }
      .nav a {
        font-size: 12px;
      }
      h1 { margin-bottom: 20px; }
      h2 { margin-top: 30px; }
      p { font-size: clamp(13px, 3vw, 14px); }
      pre {
        padding: 12px;
        font-size: 11px;
        margin: 15px -15px;
        border-radius: 0;
        overflow-x: auto;
      }
      table {
        font-size: 12px;
      }
      th, td {
        padding: 10px;
      }
      li {
        margin-left: 20px;
      }
    }
    @media (max-width: 480px) {
      .container {
        padding: 15px 12px;
      }
      .nav {
        gap: 12px;
        margin-bottom: 20px;
        font-size: 11px;
      }
      .nav a {
        font-size: 11px;
      }
      h1 { font-size: 28px; margin-bottom: 15px; }
      h2 { font-size: 20px; }
      h3 { font-size: 16px; }
      pre {
        padding: 10px;
        font-size: 10px;
      }
      footer {
        margin-top: 40px;
        padding-top: 15px;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <div class="nav">
      <a href="/">Home</a>
      <a href="/readme">Overview</a>
      <a href="/architecture">Architecture</a>
      <a href="/api">API</a>
      <a href="/security">Security</a>
      <a href="/deployment">Deployment</a>
    </div>
    ${content}
    <footer>
      <p>STVOR © 2024 • <a href="https://stvor.xyz">stvor.xyz</a></p>
    </footer>
  </div>
</body>
</html>`;
}

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
    filePath = path.join(__dirname, 'ui', 'index-new.html');
  } else if (req.url === '/dashboard' || req.url === '/dashboard.html') {
    filePath = path.join(__dirname, 'ui', 'dashboard-minimal.html');
  } else if (req.url === '/getting-started' || req.url === '/getting-started.html') {
    filePath = path.join(__dirname, 'ui', 'getting-started.html');
  } else if (req.url === '/docs' || req.url === '/documentation') {
    filePath = path.join(__dirname, 'DOCUMENTATION.md');
  } else if (req.url === '/readme') {
    filePath = path.join(__dirname, 'README.md');
  } else if (req.url === '/api') {
    filePath = path.join(__dirname, 'packages', 'sdk', 'API.md');
  } else if (req.url === '/architecture') {
    filePath = path.join(__dirname, 'ARCHITECTURE.md');
  } else if (req.url === '/security') {
    filePath = path.join(__dirname, 'SECURITY.md');
  } else if (req.url === '/deployment') {
    filePath = path.join(__dirname, 'DEPLOYMENT.md');
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
      // If markdown file, convert to HTML
      if (ext === '.md') {
        const markdown = content.toString();
        const title = path.basename(filePath, '.md');
        const htmlContent = markdownToHtml(markdown);
        const fullHtml = wrapHtml(title, htmlContent);
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(fullHtml);
      } else {
        res.writeHead(200, { 'Content-Type': contentType });
        res.end(content);
      }
    }
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 STVOR Docs: http://localhost:${PORT}/`);
  console.log(`   SDK API:    http://localhost:${PORT}/sdk-docs.html`);
  console.log(`   Bootstrap:  POST http://localhost:${PORT}/bootstrap`);
});
