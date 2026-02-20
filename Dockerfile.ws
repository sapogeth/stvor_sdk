FROM node:20-alpine

WORKDIR /app

# Install dependencies
COPY packages/sdk/package.json ./
RUN npm install

# Copy WebSocket relay server
COPY packages/sdk/relay-server.js ./relay-server.js

# Health check endpoint (simple addition)
RUN echo 'import http from "http"; http.createServer((req,res) => { if(req.url === "/health") res.end("OK"); else res.end("WS Relay"); }).listen(8000);' > health.js

# Expose WebSocket port
EXPOSE 8080
EXPOSE 8000

# Start both health check and relay
CMD ["sh", "-c", "node health.js & node relay-server.js"]