import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  submitReport,
  checkReportStatus,
  mapCategoryToH1Weakness,
  getCredentialsFromEnv,
  type H1ReportSubmission,
  type H1Credentials,
} from '../../src/hunting/platforms/hackerone.js';

describe('hackerone', () => {
  describe('mapCategoryToH1Weakness', () => {
    it('returns correct CWE ID for XSS', () => {
      expect(mapCategoryToH1Weakness('xss')).toBe(60);
    });

    it('returns correct CWE ID for SQLi', () => {
      expect(mapCategoryToH1Weakness('sqli')).toBe(67);
    });

    it('returns correct CWE ID for SSRF', () => {
      expect(mapCategoryToH1Weakness('ssrf')).toBe(918);
    });

    it('returns correct CWE ID for CSRF', () => {
      expect(mapCategoryToH1Weakness('csrf')).toBe(352);
    });

    it('returns correct CWE ID for open-redirect', () => {
      expect(mapCategoryToH1Weakness('open-redirect')).toBe(601);
    });

    it('returns correct CWE ID for command-injection', () => {
      expect(mapCategoryToH1Weakness('command-injection')).toBe(78);
    });

    it('returns correct CWE ID for race-condition', () => {
      expect(mapCategoryToH1Weakness('race-condition')).toBe(362);
    });

    it('returns correct CWE ID for prototype-pollution', () => {
      expect(mapCategoryToH1Weakness('prototype-pollution')).toBe(1321);
    });

    it('returns correct CWE ID for request-smuggling', () => {
      expect(mapCategoryToH1Weakness('request-smuggling')).toBe(444);
    });

    it('returns correct CWE ID for crlf-injection', () => {
      expect(mapCategoryToH1Weakness('crlf-injection')).toBe(93);
    });

    it('returns correct CWE ID for ldap-injection', () => {
      expect(mapCategoryToH1Weakness('ldap-injection')).toBe(90);
    });

    it('returns correct CWE ID for insecure-deserialization', () => {
      expect(mapCategoryToH1Weakness('insecure-deserialization')).toBe(502);
    });

    it('returns undefined for unknown categories', () => {
      expect(mapCategoryToH1Weakness('unknown-category')).toBeUndefined();
    });

    it('returns undefined for empty string', () => {
      expect(mapCategoryToH1Weakness('')).toBeUndefined();
    });

    it('returns undefined for typos', () => {
      expect(mapCategoryToH1Weakness('XSS')).toBeUndefined(); // case-sensitive
      expect(mapCategoryToH1Weakness('sql-injection')).toBeUndefined();
    });
  });

  describe('getCredentialsFromEnv', () => {
    const originalEnv = { ...process.env };

    afterEach(() => {
      process.env = { ...originalEnv };
    });

    it('returns null when no env vars set', () => {
      delete process.env.HACKERONE_USERNAME;
      delete process.env.HACKERONE_API_TOKEN;
      expect(getCredentialsFromEnv()).toBeNull();
    });

    it('returns null when only username set', () => {
      process.env.HACKERONE_USERNAME = 'testuser';
      delete process.env.HACKERONE_API_TOKEN;
      expect(getCredentialsFromEnv()).toBeNull();
    });

    it('returns null when only token set', () => {
      delete process.env.HACKERONE_USERNAME;
      process.env.HACKERONE_API_TOKEN = 'testtoken';
      expect(getCredentialsFromEnv()).toBeNull();
    });

    it('returns credentials when both env vars set', () => {
      process.env.HACKERONE_USERNAME = 'testuser';
      process.env.HACKERONE_API_TOKEN = 'testtoken';
      const creds = getCredentialsFromEnv();
      expect(creds).toEqual({ username: 'testuser', apiToken: 'testtoken' });
    });
  });

  describe('H1ReportSubmission type', () => {
    it('can be constructed with required fields', () => {
      const submission: H1ReportSubmission = {
        programHandle: 'security',
        title: 'Reflected XSS in search parameter',
        vulnerabilityInfo: '## Summary\nXSS found...',
        impact: 'Account takeover via session theft',
        severity: { rating: 'high' },
      };
      expect(submission.programHandle).toBe('security');
      expect(submission.severity.rating).toBe('high');
    });

    it('can be constructed with optional fields', () => {
      const submission: H1ReportSubmission = {
        programHandle: 'security',
        title: 'SQLi in login form',
        vulnerabilityInfo: '## Summary\nSQLi found...',
        impact: 'Full database access',
        severity: { rating: 'critical' },
        weaknessId: 67,
        structuredScope: { assetIdentifier: 'example.com', assetType: 'URL' },
      };
      expect(submission.weaknessId).toBe(67);
      expect(submission.structuredScope?.assetIdentifier).toBe('example.com');
    });

    it('supports all severity ratings', () => {
      const ratings: Array<'none' | 'low' | 'medium' | 'high' | 'critical'> = [
        'none', 'low', 'medium', 'high', 'critical',
      ];
      for (const rating of ratings) {
        const submission: H1ReportSubmission = {
          programHandle: 'test',
          title: 'test',
          vulnerabilityInfo: 'test',
          impact: 'test',
          severity: { rating },
        };
        expect(submission.severity.rating).toBe(rating);
      }
    });
  });

  describe('submitReport', () => {
    const originalEnv = { ...process.env };

    afterEach(() => {
      process.env = { ...originalEnv };
    });

    it('returns error when no credentials available', async () => {
      delete process.env.HACKERONE_USERNAME;
      delete process.env.HACKERONE_API_TOKEN;

      const result = await submitReport({
        programHandle: 'security',
        title: 'Test XSS',
        vulnerabilityInfo: 'Test',
        impact: 'Test',
        severity: { rating: 'high' },
      });

      expect(result.success).toBe(false);
      expect(result.error).toContain('HackerOne credentials not found');
      expect(result.error).toContain('HACKERONE_USERNAME');
      expect(result.error).toContain('HACKERONE_API_TOKEN');
    });

    it('returns success with report ID on 200 response', async () => {
      const mockResponse = {
        data: {
          id: '12345',
          type: 'report',
          attributes: {
            title: 'Test XSS',
            state: 'new',
            created_at: '2026-03-22T00:00:00Z',
            vulnerability_information: 'Test',
          },
        },
      };

      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        json: async () => mockResponse,
      } as Response);

      const result = await submitReport(
        {
          programHandle: 'security',
          title: 'Test XSS',
          vulnerabilityInfo: 'Test',
          impact: 'Test',
          severity: { rating: 'high' },
        },
        { username: 'user', apiToken: 'token' },
      );

      expect(result.success).toBe(true);
      expect(result.reportId).toBe('12345');
      expect(result.reportUrl).toBe('https://hackerone.com/reports/12345');
      expect(fetchSpy).toHaveBeenCalledOnce();

      // Verify the request body shape
      const callArgs = fetchSpy.mock.calls[0];
      expect(callArgs[0]).toBe('https://api.hackerone.com/v1/reporters/reports');
      const requestInit = callArgs[1] as RequestInit;
      expect(requestInit.method).toBe('POST');
      const parsedBody = JSON.parse(requestInit.body as string);
      expect(parsedBody.data.attributes.team_handle).toBe('security');
      expect(parsedBody.data.attributes.severity_rating).toBe('high');

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
          programHandle: 'nonexistent',
          title: 'Test',
          vulnerabilityInfo: 'Test',
          impact: 'Test',
          severity: { rating: 'medium' },
        },
        { username: 'user', apiToken: 'token' },
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('H1 API 422');
      expect(result.error).toContain('Invalid program');

      fetchSpy.mockRestore();
    });

    it('returns error on network failure', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(
        new Error('Network unreachable'),
      );

      const result = await submitReport(
        {
          programHandle: 'security',
          title: 'Test',
          vulnerabilityInfo: 'Test',
          impact: 'Test',
          severity: { rating: 'low' },
        },
        { username: 'user', apiToken: 'token' },
      );

      expect(result.success).toBe(false);
      expect(result.error).toContain('Network unreachable');

      fetchSpy.mockRestore();
    });

    it('sends correct Basic auth header', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { id: '99', type: 'report', attributes: { title: 't', state: 'new', created_at: '', vulnerability_information: '' } } }),
      } as Response);

      await submitReport(
        {
          programHandle: 'test',
          title: 'Test',
          vulnerabilityInfo: 'Test',
          impact: 'Test',
          severity: { rating: 'high' },
        },
        { username: 'myuser', apiToken: 'mytoken' },
      );

      const headers = (fetchSpy.mock.calls[0][1] as RequestInit).headers as Record<string, string>;
      const expected = 'Basic ' + Buffer.from('myuser:mytoken').toString('base64');
      expect(headers['Authorization']).toBe(expected);

      fetchSpy.mockRestore();
    });

    it('includes weakness_id when provided', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        json: async () => ({ data: { id: '100', type: 'report', attributes: { title: 't', state: 'new', created_at: '', vulnerability_information: '' } } }),
      } as Response);

      await submitReport(
        {
          programHandle: 'test',
          title: 'SQLi',
          vulnerabilityInfo: 'SQL injection found',
          impact: 'Full DB access',
          severity: { rating: 'critical' },
          weaknessId: 67,
        },
        { username: 'u', apiToken: 't' },
      );

      const parsedBody = JSON.parse((fetchSpy.mock.calls[0][1] as RequestInit).body as string);
      expect(parsedBody.data.attributes.weakness_id).toBe(67);

      fetchSpy.mockRestore();
    });
  });

  describe('checkReportStatus', () => {
    const originalEnv = { ...process.env };

    afterEach(() => {
      process.env = { ...originalEnv };
    });

    it('returns unknown state when no credentials', async () => {
      delete process.env.HACKERONE_USERNAME;
      delete process.env.HACKERONE_API_TOKEN;

      const result = await checkReportStatus('12345');
      expect(result.state).toBe('unknown');
      expect(result.error).toBe('No credentials');
    });

    it('returns report state on success', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: true,
        json: async () => ({
          data: {
            attributes: { state: 'triaged' },
            relationships: { bounties: { data: [{ attributes: { amount: 500 } }] } },
          },
        }),
      } as Response);

      const result = await checkReportStatus('12345', { username: 'u', apiToken: 't' });
      expect(result.state).toBe('triaged');
      expect(result.bountyAmount).toBe(500);

      fetchSpy.mockRestore();
    });

    it('returns unknown on API error', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce({
        ok: false,
        status: 404,
      } as Response);

      const result = await checkReportStatus('99999', { username: 'u', apiToken: 't' });
      expect(result.state).toBe('unknown');
      expect(result.error).toContain('404');

      fetchSpy.mockRestore();
    });

    it('returns unknown on network failure', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(
        new Error('Connection refused'),
      );

      const result = await checkReportStatus('12345', { username: 'u', apiToken: 't' });
      expect(result.state).toBe('unknown');
      expect(result.error).toContain('Connection refused');

      fetchSpy.mockRestore();
    });
  });
});
