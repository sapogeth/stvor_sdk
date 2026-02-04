import * as crypto from 'crypto';
import { createApiKey as storageCreateApiKey, getProjectIdByApiKey as storageGetProjectId, createProject as storageCreateProject, importApiKey } from '../storage/json.js';
// Generate API key (32 bytes hex = 64 chars)
export function generateApiKey() {
    return crypto.randomBytes(32).toString('hex');
}
export function storeApiKey(apiKey, projectId) {
    importApiKey(apiKey, projectId);
}
export function getProjectIdByApiKey(apiKey) {
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
