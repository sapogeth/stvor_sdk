import * as crypto from 'crypto';
import { 
  createApiKey as storageCreateApiKey, 
  getProjectIdByApiKey as storageGetProjectId,
  createProject as storageCreateProject,
  importApiKey
} from '../storage/json.js';

// Generate API key (32 bytes hex = 64 chars)
export function generateApiKey(): string {
  return crypto.randomBytes(32).toString('hex');
}

export function storeApiKey(apiKey: string, projectId: string) {
  importApiKey(apiKey, projectId);
}

export function getProjectIdByApiKey(apiKey: string): string | undefined {
  return storageGetProjectId(apiKey);
}

export function createProjectWithApiKey() {
  const projectId = crypto.randomUUID();
  const apiKey = generateApiKey();
  
  // Create project and api key
  storageCreateProject(projectId);
  storageCreateApiKey(apiKey, projectId);
  
  return { projectId, apiKey };
}
