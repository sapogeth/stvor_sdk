'use strict';

// Auto-generated CommonJS wrapper for facade/errors.js
// This allows `require('@stvor/sdk')` to work alongside ESM `import`.

const mod = require('module');
const url = require('url');

// Use dynamic import to load the ESM module
let _cached;
async function _load() {
  if (!_cached) {
    _cached = await import(url.pathToFileURL(__filename.replace(/\.cjs$/, '.js')).href);
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
