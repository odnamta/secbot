import { describe, it, expect } from 'vitest';
import { buildConfig } from '../../src/config/defaults.js';

describe('--auth-header (extraHeaders)', () => {
  it('should pass extraHeaders through buildConfig', () => {
    const config = buildConfig('https://example.com', {
      extraHeaders: { Authorization: 'Bearer test-token-123' },
    });
    expect(config.extraHeaders).toEqual({ Authorization: 'Bearer test-token-123' });
  });

  it('should support custom header names', () => {
    const config = buildConfig('https://example.com', {
      extraHeaders: { 'X-API-Key': 'sk-abc123' },
    });
    expect(config.extraHeaders).toEqual({ 'X-API-Key': 'sk-abc123' });
  });

  it('should be undefined when not provided', () => {
    const config = buildConfig('https://example.com');
    expect(config.extraHeaders).toBeUndefined();
  });

  it('should support multiple headers', () => {
    const config = buildConfig('https://example.com', {
      extraHeaders: {
        Authorization: 'Bearer token',
        'X-Custom': 'value',
      },
    });
    expect(config.extraHeaders).toEqual({
      Authorization: 'Bearer token',
      'X-Custom': 'value',
    });
  });
});
