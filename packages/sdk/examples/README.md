# STVOR SDK — Examples

This directory contains working examples for different module systems.

## Prerequisites

1. Install the SDK:
   ```bash
   npm install @stvor/sdk
   ```

2. Start the mock relay server:
   ```bash
   npx @stvor/sdk mock-relay
   ```

## Examples

### ESM (ECMAScript Modules) — Recommended

```bash
node examples/esm-example.mjs
```

Your `package.json`:
```json
{
  "type": "module",
  "dependencies": {
    "@stvor/sdk": "^2.4.0"
  }
}
```

### CommonJS (require)

```bash
node examples/commonjs-example.cjs
```

Your `package.json`:
```json
{
  "dependencies": {
    "@stvor/sdk": "^2.4.0"
  }
}
```

> **Note:** CommonJS requires the async `sdk.load()` pattern since the SDK
> is an ES Module internally. This is handled transparently.

### TypeScript

```bash
npx tsx examples/typescript-example.ts
```

Your `tsconfig.json`:
```json
{
  "compilerOptions": {
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "esModuleInterop": true,
    "target": "ES2020"
  }
}
```

## Package.json Templates

### ESM Project (Recommended)

```json
{
  "name": "my-stvor-app",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "start": "node app.js",
    "dev": "node --watch app.js",
    "relay": "npx @stvor/sdk mock-relay"
  },
  "dependencies": {
    "@stvor/sdk": "^2.4.0"
  }
}
```

### CommonJS Project

```json
{
  "name": "my-stvor-app-cjs",
  "version": "1.0.0",
  "scripts": {
    "start": "node app.js",
    "dev": "node --watch app.js",
    "relay": "npx @stvor/sdk mock-relay"
  },
  "dependencies": {
    "@stvor/sdk": "^2.4.0"
  }
}
```

### TypeScript Project

```json
{
  "name": "my-stvor-app-ts",
  "version": "1.0.0",
  "type": "module",
  "scripts": {
    "start": "tsx app.ts",
    "build": "tsc",
    "dev": "tsx --watch app.ts",
    "relay": "npx @stvor/sdk mock-relay"
  },
  "dependencies": {
    "@stvor/sdk": "^2.4.0"
  },
  "devDependencies": {
    "tsx": "^4.0.0",
    "typescript": "^5.0.0"
  }
}
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `STVOR_APP_TOKEN` | — | Your AppToken (must start with `stvor_`) |
| `RELAY_URL` | `ws://localhost:4444` | Relay server WebSocket URL |
| `STVOR_MOCK_PORT` | `4444` | Mock relay server port |
| `STVOR_MOCK_VERBOSE` | `0` | Set to `1` for verbose mock relay logs |

## Interactive Examples

For a zero-setup experience, try the SDK directly in your browser:

- **CodeSandbox**: [Open STVOR SDK Template](https://codesandbox.io/s/stvor-sdk-quickstart) *(link available when published)*
- **StackBlitz**: [Open STVOR SDK Template](https://stackblitz.com/edit/stvor-sdk-quickstart) *(link available when published)*

These sandboxes include a pre-configured mock relay running in-browser,
so you can test E2E encryption without any local setup.

## Troubleshooting

See [docs/TROUBLESHOOTING.md](../docs/TROUBLESHOOTING.md) for common errors
and their solutions.
