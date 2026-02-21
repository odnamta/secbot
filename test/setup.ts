import type { Server } from 'node:http';
import { createVulnerableServer } from './fixtures/vulnerable-server.js';

let server: Server;
let baseUrl = '';

export async function startTestServer(): Promise<string> {
  const { server: s, url } = await createVulnerableServer();
  server = s;
  baseUrl = url;
  return url;
}

export async function stopTestServer(): Promise<void> {
  return new Promise((resolve) => {
    if (!server) return resolve();
    const timeout = setTimeout(() => {
      server.closeAllConnections?.();
      resolve();
    }, 3000);
    server.close(() => {
      clearTimeout(timeout);
      resolve();
    });
  });
}

export function getTestUrl(): string {
  if (!baseUrl) throw new Error('Test server not started. Call startTestServer() first.');
  return baseUrl;
}
