#!/usr/bin/env node
/**
 * Generate static HTML files from markdown for Vercel deployment
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Markdown to HTML converter (same as serve.mjs)
function markdownToHtml(markdown) {
  let html = markdown
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  html = html.replace(/```([\s\S]*?)```/g, (match, code) => {
    return '<pre><code>' + code.trim() + '</code></pre>';
  });

  html = html.replace(/^### (.*?)$/gm, '<h3>$1</h3>');
  html = html.replace(/^## (.*?)$/gm, '<h2>$1</h2>');
  html = html.replace(/^# (.*?)$/gm, '<h1>$1</h1>');

  html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/\*(.*?)\*/g, '<em>$1</em>');

  html = html.replace(/\[(.*?)\]\((.*?)\)/g, '<a href="$2">$1</a>');

  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

  html = html.replace(/^\- (.*?)$/gm, '<li>$1</li>');
  html = html.replace(/(<li>.*?<\/li>)/s, '<ul>$1</ul>');

  html = html.replace(/\n\n+/g, '</p><p>');
  html = '<p>' + html + '</p>';
  html = html.replace(/<p><\/p>/g, '');
  html = html.replace(/<p>(<h[1-3])/g, '$1');
  html = html.replace(/(<\/h[1-3]>)<\/p>/g, '$1');
  html = html.replace(/<p>(<pre>)/g, '$1');
  html = html.replace(/(<\/pre>)<\/p>/g, '$1');
  html = html.replace(/<p>(<ul>)/g, '$1');
  html = html.replace(/(<\/ul>)<\/p>/g, '$1');

  return html;
}

// HTML wrapper template
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
      <a href="/readme.html">Overview</a>
      <a href="/architecture.html">Architecture</a>
      <a href="/api.html">API</a>
      <a href="/security.html">Security</a>
      <a href="/deployment.html">Deployment</a>
    </div>
    ${content}
    <footer>
      <p>STVOR © 2024 • <a href="https://stvor.xyz">stvor.xyz</a></p>
    </footer>
  </div>
</body>
</html>`;
}

// Generate HTML files
const docs = [
  { md: 'README.md', html: 'readme.html' },
  { md: 'ARCHITECTURE.md', html: 'architecture.html' },
  { md: 'SECURITY.md', html: 'security.html' },
  { md: 'DEPLOYMENT.md', html: 'deployment.html' },
  { md: 'packages/sdk/API.md', html: 'api.html' },
];

console.log('🔨 Building static HTML files for Vercel...\n');

for (const doc of docs) {
  try {
    const mdPath = path.join(__dirname, doc.md);
    const htmlPath = path.join(__dirname, doc.html);
    
    const markdown = fs.readFileSync(mdPath, 'utf-8');
    const htmlContent = markdownToHtml(markdown);
    const title = path.basename(doc.md, '.md');
    const fullHtml = wrapHtml(title, htmlContent);
    
    fs.writeFileSync(htmlPath, fullHtml, 'utf-8');
    console.log(`✓ Generated ${doc.html}`);
  } catch (err) {
    console.error(`✗ Error generating ${doc.html}:`, err.message);
  }
}

console.log('\n✅ Build complete! HTML files ready for Vercel.');
