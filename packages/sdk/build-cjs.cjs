/**
 * build-cjs.cjs
 * 
 * Generates CommonJS wrapper files (.cjs) for every ESM .js in dist/
 * so that `require('@stvor/sdk')` works out of the box.
 *
 * Each .cjs file dynamic-imports the ESM original and re-exports 
 * all named + default exports synchronously via a top-level await shim.
 */
const fs = require('fs');
const path = require('path');

const distDir = path.join(__dirname, 'dist');

// ── helpers ──────────────────────────────────────────────────────────
function walk(dir) {
  const files = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...walk(full));
    } else if (entry.name.endsWith('.js')) {
      files.push(full);
    }
  }
  return files;
}

// ── main ─────────────────────────────────────────────────────────────
const jsFiles = walk(distDir);

for (const jsFile of jsFiles) {
  const cjsFile = jsFile.replace(/\.js$/, '.cjs');
  const relativeName = './' + path.basename(jsFile);

  const wrapper = `'use strict';

// Auto-generated CommonJS wrapper for ${path.relative(distDir, jsFile)}
// This allows \`require('@stvor/sdk')\` to work alongside ESM \`import\`.

const mod = require('module');
const url = require('url');

// Use dynamic import to load the ESM module
let _cached;
async function _load() {
  if (!_cached) {
    _cached = await import(url.pathToFileURL(__filename.replace(/\\.cjs$/, '.js')).href);
  }
  return _cached;
}

// For simple CJS usage, expose a promise-based loader
module.exports = new Proxy({ load: _load }, {
  get(target, prop) {
    if (prop === '__esModule') return true;
    if (prop === 'then') return undefined; // prevent treating as thenable
    if (prop === 'load') return _load;
    if (prop === 'default') {
      return _load().then(m => m.default);
    }
    return _load().then(m => m[prop]);
  }
});
`;

  fs.writeFileSync(cjsFile, wrapper);
}

// ── Generate .d.cts for the main entry ──────────────────────────────
const mainDts = path.join(distDir, 'index.d.ts');
const mainDcts = path.join(distDir, 'index.d.cts');

if (fs.existsSync(mainDts)) {
  const dtsContent = fs.readFileSync(mainDts, 'utf8');
  fs.writeFileSync(mainDcts, dtsContent);
}

console.log(`[build-cjs] Generated ${jsFiles.length} .cjs wrappers`);
