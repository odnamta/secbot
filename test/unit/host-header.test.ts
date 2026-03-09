import { describe, it, expect } from 'vitest';
import {
  HOST_CANARY,
  INJECTION_HEADERS,
  detectCanaryReflection,
  hostHeaderCheck,
} from '../../src/scanner/active/host-header.js';

describe('Host Header Injection — Unit Tests', () => {
  describe('metadata', () => {
    it('has correct name', () => {
      expect(hostHeaderCheck.name).toBe('host-header');
    });

    it('has correct category', () => {
      expect(hostHeaderCheck.category).toBe('host-header');
    });
  });

  describe('HOST_CANARY', () => {
    it('is the expected canary domain', () => {
      expect(HOST_CANARY).toBe('secbot-host-inject.example.com');
    });
  });

  describe('INJECTION_HEADERS', () => {
    it('includes X-Forwarded-Host', () => {
      expect(INJECTION_HEADERS).toContain('X-Forwarded-Host');
    });

    it('includes X-Forwarded-Server', () => {
      expect(INJECTION_HEADERS).toContain('X-Forwarded-Server');
    });

    it('includes X-Original-URL', () => {
      expect(INJECTION_HEADERS).toContain('X-Original-URL');
    });

    it('includes X-Rewrite-URL', () => {
      expect(INJECTION_HEADERS).toContain('X-Rewrite-URL');
    });

    it('has 4 injection headers', () => {
      expect(INJECTION_HEADERS).toHaveLength(4);
    });
  });

  describe('detectCanaryReflection()', () => {
    it('detects canary in Location header', () => {
      const headers: Record<string, string> = {
        location: `https://${HOST_CANARY}/login`,
        'content-type': 'text/html',
      };
      const result = detectCanaryReflection('', headers);
      expect(result).not.toBeNull();
      expect(result!.location).toBe('header');
      expect(result!.evidence).toContain('Location:');
      expect(result!.evidence).toContain(HOST_CANARY);
    });

    it('detects canary in response body', () => {
      const headers: Record<string, string> = {
        'content-type': 'text/html',
      };
      const body = `<html><head><link href="https://${HOST_CANARY}/style.css"></head></html>`;
      const result = detectCanaryReflection(body, headers);
      expect(result).not.toBeNull();
      expect(result!.location).toBe('body');
      expect(result!.evidence).toContain(HOST_CANARY);
    });

    it('prioritizes Location header over body', () => {
      const headers: Record<string, string> = {
        location: `https://${HOST_CANARY}/redirect`,
      };
      const body = `<a href="https://${HOST_CANARY}/link">Click</a>`;
      const result = detectCanaryReflection(body, headers);
      expect(result).not.toBeNull();
      expect(result!.location).toBe('header');
    });

    it('returns null when canary is not reflected', () => {
      const headers: Record<string, string> = {
        location: 'https://example.com/normal',
        'content-type': 'text/html',
      };
      const body = '<html><body>Normal page</body></html>';
      const result = detectCanaryReflection(body, headers);
      expect(result).toBeNull();
    });

    it('returns null for empty body and no Location header', () => {
      const result = detectCanaryReflection('', {});
      expect(result).toBeNull();
    });

    it('returns null when Location header is missing', () => {
      const headers: Record<string, string> = {
        'content-type': 'text/html',
      };
      const result = detectCanaryReflection('normal content', headers);
      expect(result).toBeNull();
    });

    it('extracts context around canary in body', () => {
      const prefix = 'A'.repeat(100);
      const suffix = 'B'.repeat(100);
      const body = `${prefix}${HOST_CANARY}${suffix}`;
      const result = detectCanaryReflection(body, {});
      expect(result).not.toBeNull();
      expect(result!.location).toBe('body');
      // Evidence should contain surrounding context, not the full body
      expect(result!.evidence.length).toBeLessThan(body.length);
      expect(result!.evidence).toContain(HOST_CANARY);
    });
  });
});
