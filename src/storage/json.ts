/**
 * STVOR Persistent Storage (JSON file)
 * 
 * Data structure:
 * {
 *   "projects": { "id": { "created_at": timestamp } },
 *   "api_keys": {
 *     "key": { "project_id": "id", "created_at": timestamp, "revoked_at": timestamp|null, "status": "active"|"revoked" }
 *   }
 * }
 */

import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATA_PATH = path.join(__dirname, '../../data/stvor.json');

interface Project {
  created_at: number;
}

interface ApiKeyRecord {
  project_id: string;
  created_at: number;
  revoked_at: number | null;
  status: 'active' | 'revoked';
}

interface StorageData {
  projects: Record<string, Project>;
  api_keys: Record<string, ApiKeyRecord>;
}

let data: StorageData = {
  projects: {},
  api_keys: {},
};

function loadData() {
  try {
    if (fs.existsSync(DATA_PATH)) {
      const content = fs.readFileSync(DATA_PATH, 'utf-8');
      data = JSON.parse(content);
      console.log(`[Storage] Loaded ${Object.keys(data.api_keys).length} API keys from disk`);
    }
  } catch (e) {
    console.error('[Storage] Failed to load data:', e);
  }
}

function saveData() {
  try {
    const dir = path.dirname(DATA_PATH);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
    fs.writeFileSync(DATA_PATH, JSON.stringify(data, null, 2));
  } catch (e) {
    console.error('[Storage] Failed to save data:', e);
  }
}

export function initStorage() {
  loadData();
  // Save on process exit
  process.on('exit', saveData);
  return data;
}

// Project operations
export function createProject(projectId: string) {
  data.projects[projectId] = { created_at: Date.now() };
  saveData();
  return { id: projectId };
}

export function getProjectById(projectId: string) {
  return data.projects[projectId] as { id: string; created_at: number } | undefined;
}

// API Key operations
export function createApiKey(apiKey: string, projectId: string) {
  data.api_keys[apiKey] = {
    project_id: projectId,
    created_at: Date.now(),
    revoked_at: null,
    status: 'active',
  };
  saveData();
  return { key: apiKey, project_id: projectId };
}

export function validateApiKey(apiKey: string): { valid: boolean; projectId?: string; reason?: string } {
  const record = data.api_keys[apiKey];
  
  if (!record) {
    return { valid: false, reason: 'API key not found' };
  }

  if (record.status === 'revoked') {
    return { valid: false, reason: 'API key revoked' };
  }

  return { valid: true, projectId: record.project_id };
}

export function revokeApiKey(apiKey: string) {
  const record = data.api_keys[apiKey];
  if (record) {
    record.status = 'revoked';
    record.revoked_at = Date.now();
    saveData();
    return { revoked: true };
  }
  return { revoked: false };
}

export function getProjectIdByApiKey(apiKey: string): string | undefined {
  const result = validateApiKey(apiKey);
  return result.valid ? result.projectId : undefined;
}

// Import key (for migration)
export function importApiKey(apiKey: string, projectId: string) {
  data.api_keys[apiKey] = {
    project_id: projectId,
    created_at: Date.now(),
    revoked_at: null,
    status: 'active',
  };
  saveData();
}

// Migration from in-memory Map
export function migrateFromMemory(apiKeys: Map<string, string>) {
  let count = 0;
  for (const [key, projectId] of apiKeys) {
    if (!data.api_keys[key]) {
      data.api_keys[key] = {
        project_id: projectId,
        created_at: Date.now(),
        revoked_at: null,
        status: 'active',
      };
      count++;
    }
  }
  if (count > 0) {
    saveData();
  }
  return count;
}
