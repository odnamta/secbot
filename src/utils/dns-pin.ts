import { resolve4 } from 'node:dns/promises';

const PRIVATE_RANGES = [
  /^10\./,
  /^172\.(1[6-9]|2\d|3[01])\./,
  /^192\.168\./,
  /^127\./,
  /^0\./,
  /^169\.254\./,
  /^::1$/,
  /^fc00:/,
  /^fe80:/,
];

export function isPrivateIP(ip: string): boolean {
  return PRIVATE_RANGES.some(r => r.test(ip));
}

export function truncateResponse(body: string, maxBytes: number = 1_048_576): string {
  if (body.length <= maxBytes) return body;
  return body.slice(0, maxBytes);
}

export const RESOURCE_LIMITS = {
  maxRedirects: 10,
  maxResponseBytes: 1_048_576, // 1MB
  maxRequestTimeout: 30_000, // 30 seconds
  maxWebSocketMessages: 100,
  maxConcurrentPages: 5,
} as const;

export class DnsPinner {
  private cache = new Map<string, string[]>();

  async resolve(hostname: string): Promise<string[]> {
    if (this.cache.has(hostname)) return this.cache.get(hostname)!;
    try {
      const ips = await resolve4(hostname);
      this.cache.set(hostname, ips);
      return ips;
    } catch {
      return [];
    }
  }

  async isAllowed(hostname: string, allowPrivate = false): Promise<boolean> {
    // Always allow if explicitly private (internal scanning)
    if (allowPrivate) return true;
    const ips = await this.resolve(hostname);
    if (ips.length === 0) return false;
    return !ips.some(ip => isPrivateIP(ip));
  }

  getCached(hostname: string): string[] | undefined {
    return this.cache.get(hostname);
  }

  clearCache(): void {
    this.cache.clear();
  }
}

// Sanitize evidence for AI prompts — prevent prompt injection
export function sanitizeEvidence(evidence: string, maxLength: number = 5000): string {
  let sanitized = evidence;
  // Truncate
  if (sanitized.length > maxLength) {
    sanitized = sanitized.slice(0, maxLength) + '...[truncated]';
  }
  // Strip common prompt injection patterns
  const injectionPatterns = [
    /ignore\s+(all\s+)?previous\s+instructions/gi,
    /you\s+are\s+now\s+/gi,
    /system\s*:\s*/gi,
    /\<\/?system\>/gi,
    /\<\/?assistant\>/gi,
    /\<\/?human\>/gi,
    /\<\/?user\>/gi,
    /IMPORTANT\s*:\s*override/gi,
    /forget\s+(all\s+)?previous/gi,
    /new\s+instructions?\s*:/gi,
  ];
  for (const pattern of injectionPatterns) {
    sanitized = sanitized.replace(pattern, '[FILTERED]');
  }
  return sanitized;
}
