module.exports = {
  apps: [
    {
      name: 'stvor-api',
      script: 'dist/server.js',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '1G',
      env: {
        NODE_ENV: 'production',
        PORT: '3001',
        RELAY_PORT: '3002',
        DB_HOST: 'localhost',
        DB_PORT: '5433',
        DB_USER: 'postgres', 
        DB_PASSWORD: 'stvor123',
        DB_NAME: 'stvor'
      }
    },
    {
      name: 'stvor-ws-relay',
      script: 'packages/sdk/relay-server.js',
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: '512M',
      env: {
        PORT: '8080'
      }
    }
  ]
};