/**
 * STVOR API Authentication Middleware
 * 
 * Auth Model:
 * - API key represents PROJECT identity (not user identity)
 * - Grants: access to project-specific resources (users, messages)
 * - Does NOT grant: ability to decrypt messages (E2EE)
 * - Does NOT grant: access to other projects' data
 */

import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import { getProjectIdByApiKey } from '../auth/apiKey.js';

// Public routes that don't require authentication
const PUBLIC_ROUTES = [
  '/',
  '/index.html',
  '/health',
  '/docs',
  '/docs/',
  '/docs/index.html',
  '/__routes', // debug route
  '/bootstrap', // TEMP: for creating first API key
  '/import-key', // TEMP: for importing existing API key
];

// Routes that need authentication but are defined in server.ts
// These should be checked by their handler, not by global middleware
const SKIP_GLOBAL_AUTH = [
  '/usage',
  '/limits',
  '/api/projects',
];

// Error response factory
export function authError(reply: FastifyReply, code: string, message: string) {
  return reply.status(code === 'API_KEY_REQUIRED' ? 401 : 403).send({
    error: code,
    message,
  });
}

// API Key validation middleware
export async function authMiddleware(
  request: FastifyRequest,
  reply: FastifyReply
) {
  const url = request.url;

  // Allow public routes
  if (PUBLIC_ROUTES.some(route => url.startsWith(route))) {
    return;
  }

  // Skip global auth for routes that handle auth themselves
  if (SKIP_GLOBAL_AUTH.some(route => url.startsWith(route))) {
    return;
  }

  // Extract API key from Authorization header
  const authHeader = request.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return authError(
      reply,
      'API_KEY_REQUIRED',
      'API key is required to access this endpoint. Include "Authorization: Bearer <API_KEY>" header.'
    );
  }

  const apiKey = authHeader.substring(7); // Remove 'Bearer ' prefix

  // Validate API key
  const projectId = getProjectIdByApiKey(apiKey);
  if (!projectId) {
    return authError(
      reply,
      'API_KEY_INVALID',
      'Invalid or revoked API key. Check your credentials or generate a new key.'
    );
  }

  // Attach project context to request
  (request as any).projectId = projectId;
  (request as any).apiKey = apiKey;
}

// Register auth middleware globally
export function registerAuthMiddleware(app: FastifyInstance) {
  app.addHook('onRequest', authMiddleware);
}

// Helper to get project ID from request
export function getProjectId(request: FastifyRequest): string | null {
  return (request as any).projectId || null;
}

