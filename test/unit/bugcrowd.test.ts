import { describe, it, expect, vi, afterEach } from 'vitest';
import {
  submitReport,
  checkSubmissionStatus,
  mapSeverityToBC,
  mapCategoryToCWE,
  getCredentialsFromEnv,
  type BCSubmission,
  type BugcrowdCredentials,
} from '../../src/hunting/platforms/bugcrowd.js';

describe('bugcrowd', () => {
  describe('mapSeverityToBC', () => {
    it('returns P1 for critical', () => {
      expect(mapSeverityToBC('critical')).toBe(1);
    });

    it('returns P2 for high', () => {
      expect(mapSeverityToBC('high')).toBe(2);
    });

    it('returns P3 for medium', () => {
      expect(mapSeverityToBC('medium')).toBe(3);
    });

    it('returns P4 for low', () => {
      expect(mapSeverityToBC('low')).toBe(4);
    });

    it('returns P5 for info', () => {
      expect(mapSeverityToBC('info')).toBe(5);
    });

    it('defaults to P3 for unknown severity', () => {
      expect(mapSeverityToBC('unknown')).toBe(3);
    });

    it('defaults to P3 for empty string', () => {
      expect(mapSeverityToBC('')).toBe(3);
    });
  });

  describe('mapCategoryToCWE', () => {
    it('returns correct CWE for XSS', () => {
      expect(mapCategoryToCWE('xss')).toBe('CWE-79');
    });

    it('returns correct CWE for SQLi', () => {
      expect(mapCategoryToCWE('sqli')).toBe('CWE-89');
    });

    it('returns correct CWE for SSRF', () => {
      expect(mapCategoryToCWE('ssrf')).toBe('CWE-918');
    });

    it('returns correct CWE for CSRF', () => {
      expect(mapCategoryToCWE('csrf')).toBe('CWE-352');
    });

    it('returns correct CWE for command-injection', () => {
      expect(mapCategoryToCWE('command-injection')).toBe('CWE-78');
    });

    it('returns correct CWE for prototype-pollution', () => {
      expect(mapCategoryToCWE('prototype-pollution')).toBe('CWE-1321');
    });

    it('returns correct CWE for request-smuggling', () => {
      expect(mapCategoryToCWE('request-smuggling')).toBe('CWE-444');
    });

    it('returns undefined for unknown categories', () => {
      expect(mapCategoryToCWE('unknown-category')).toBeUndefined();
    });

    it('returns undefined for empty string', () => {
      expect(mapCategoryToCWE('')).toBeUndefined();
    });

    it('returns undefined for typos', () => {
      expect(mapCategoryToCWE('XSS')).toBeUndefined(); // case-sensitive
      expect(mapCategoryToCWE('sql-injection')).toBeUndefined();
    });
  });

  describe('getCredentialsFromEnv', () => {
    const originalEnv = { ...process.env };

    afterEach(() => {
      process.env = { ...originalEnv };
    });

    it('returns null when no env var set', () => {
      delete process.env.BUGCROWD_API_TOKEN;
      expect(getCredentialsFromEnv()).toBeNull();
    });

    it('returns credentials when env var set', () => {
      process.env.BUGCROWD_API_TOKEN = 'bc-test-token';
      const creds = getCredentialsFromEnv();
      expect(creds).toEqual({ apiToken: 'bc-test-token' });
    });
  });

  describe('BCSubmission type', () => {
    it('can be constructed with required fields', () => {
      const submission: BCSubmission = {
        programId: 'abc-123-uuid',
        title: 'Reflected XSS in search parameter',
        description: '## Summary\nXSS found...',
        severity: 2,
        vulnerabilityRefs: ['CWE-79'],
      };
      expect(submission.programId).toBe('abc-123-uuid');
      expect(submission.severity).toBe(2);
    });

    it('supports all severity levels', () => {
      const levels: Array<1 | 2 | 3 | 4 | 5> = [1, 2, 3, 4, 5];
      for (const severity of levels) {
        const submission: BCSubmission = {
          programId: 'test-uuid',
          title: 'test',
          description: 'test',
          severity,
          vulnerabilityRefs: [],
        };
        expect(submission.severity).toBe(severity);
      }
    });

    it('supports multiple vulnerability references', () => {
      const submission: BCSubmission = {
        programId: 'test-uuid',
        title: 'Chained vulnerability',
        description: 'XSS + CSRF chain',
        severity: 1,
        vulnerabilityRefs: ['CWE-79', 'CWE-352'],
      };
      expect(submission.vulnerabilityRefs).toHaveLength(2);
    });
  });

  describe('submitReport', () => {
    const originalEnv = { ...process.env };

    afterEach(() => {
      process.env = { ...originalEnv };
    });

    it('returns error when no credentials available', async () => {
      delete process.env.BUGCROWD_API_TOKEN;

      const result = await submitReport({
        programId: 'test-uuid',
        title: 'Test XSS',
        description: 'Test',
        severity: 2,
        vulnerabilityRefs: ['CWE-79'],
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('Bugcrowd credentials not found');
      expect(result.error).toContain('BUGCROWD_API_TOKEN');
    });

    it('returns success with submission ID on 200 response', async () => {
      const mockResponse = {
        data: {
          id: 'sub-456',
          type: 'submission',
          attributes: {
            title: 'Test XSS',
            state: 'new',
            severity: 2,
            submitted_at: '2026-03-22T00:00:00Z',
          },
        },
      };

      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      } as Response);

      const result = await submitReport(
        {
          programId: 'prog-uuid',
          title: 'Test XSS',
          description: 'Found XSS',
          severity: 2,
          vulnerabilityRefs: ['CWE-79'],
        },
        { apiToken: 'bc-token' },
      );

      expect(result.success).toBe(true);
      expect(result.submissionId).toBe('sub-456');
      expect(result.submissionUrl).toBe('https://bugcrowd.com/submissions/sub-456');
      expect(fetchSpy).toHaveBeenCalledOnce();

      // Verify the request body shape
      const callArgs = fetchSpy.mock.calls[0];
      expect(callArgs[0]).toBe('https://api.bugcrowd.com/submissions');
      const requestInit = callArgs[1] as RequestInit;
      expect(requestInit.method).toBe('POST');
      const parsedBody = JSON.parse(requestInit.body as string);
      expect(parsedBody.data.type).toBe('submission');
      expect(parsedBody.data.attributes.title).toBe('Test XSS');
      expect(parsedBody.data.attributes.severity).toBe(2);
      expect(parsedBody.data.relationships.program.data.id).toBe('prog-uuid');

      fetchSpy.mockRestore();
    });

    it('returns error on non-OK response', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: false,
        status: 422,
        text: async () => '{"errors":[{"title":"Invalid program"}]}',
      } as Response);

      const result = await submitReport(
        {
          programId: 'nonexistent',
          title: 'Test',
          description: 'Test',
          severity: 3,
          vulnerabilityRefs: [],
        },
        { apiToken: 'bc-token' },
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('BC API 422');
      expect(result.error).toContain('Invalid program');

      fetchSpy.mockRestore();
    });

    it('returns error on network failure', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(
        new Error('Network unreachable'),
      );

      const result = await submitReport(
        {
          programId: 'prog-uuid',
          title: 'Test',
          description: 'Test',
          severity: 4,
          vulnerabilityRefs: [],
        },
        { apiToken: 'bc-token' },
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Network unreachable');

      fetchSpy.mockRestore();
    });

    it('sends correct Bearer token auth header', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { id: 'sub-99', type: 'submission', attributes: { title: 't', state: 'new', severity: 3, submitted_at: '' } } }),
      } as Response);

      await submitReport(
        {
          programId: 'test',
          title: 'Test',
          description: 'Test',
          severity: 3,
          vulnerabilityRefs: [],
        },
        { apiToken: 'my-secret-token' },
      );

      const headers = (fetchSpy.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
      expect(headers['Authorization']).toBe('Token my-secret-token');
      expect(headers['Content-Type']).toBe('application/vnd.bugcrowd+json');
      expect(headers['Accept']).toBe('application/vnd.bugcrowd+json');

      fetchSpy.mockRestore();
    });

    it('includes vulnerability references in body', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { id: 'sub-100', type: 'submission', attributes: { title: 't', state: 'new', severity: 1, submitted_at: '' } } }),
      } as Response);

      await submitReport(
        {
          programId: 'test',
          title: 'SQLi',
          description: 'SQL injection found',
          severity: 1,
          vulnerabilityRefs: ['CWE-89', 'CWE-200'],
        },
        { apiToken: 'token' },
      );

      const parsedBody = JSON.parse((fetchSpy.mock.calls[0][1] as RequestInit).body as string);
      expect(parsedBody.data.attributes.vulnerability_references).toEqual([
        { type: 'cwe', reference: 'CWE-89' },
        { type: 'cwe', reference: 'CWE-200' },
      ]);

      fetchSpy.mockRestore();
    });
  });

  describe('checkSubmissionStatus', () => {
    const originalEnv = { ...process.env };

    afterEach(() => {
      process.env = { ...originalEnv };
    });

    it('returns unknown state when no credentials', async () => {
      delete process.env.BUGCROWD_API_TOKEN;

      const result = await checkSubmissionStatus('sub-123');
      expect(result.state).toBe('unknown');
      expect(result.error).toBe('No credentials');
    });

    it('returns submission state on success', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          data: {
            attributes: { state: 'triaged', severity: 2 },
          },
        }),
      } as Response);

      const result = await checkSubmissionStatus('sub-123', { apiToken: 'token' });
      expect(result.state).toBe('triaged');
      expect(result.severity).toBe(2);

      fetchSpy.mockRestore();
    });

    it('returns unknown on API error', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: false,
        status: 404,
      } as Response);

      const result = await checkSubmissionStatus('sub-99999', { apiToken: 'token' });
      expect(result.state).toBe('unknown');
      expect(result.error).toContain('404');

      fetchSpy.mockRestore();
    });

    it('returns unknown on network failure', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(
        new Error('Connection refused'),
      );

      const result = await checkSubmissionStatus('sub-123', { apiToken: 'token' });
      expect(result.state).toBe('unknown');
      expect(result.error).toContain('Connection refused');

      fetchSpy.mockRestore();
    });

    it('fetches from correct URL with auth', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { attributes: { state: 'new' } } }),
      } as Response);

      await checkSubmissionStatus('sub-xyz', { apiToken: 'my-token' });

      expect(fetchSpy.mock.calls[0][0]).toBe('https://api.bugcrowd.com/submissions/sub-xyz');
      const headers = (fetchSpy.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
      expect(headers['Authorization']).toBe('Token my-token');

      fetchSpy.mockRestore();
    });
  });
});
