import { describe, it, expect, vi } from 'vitest';

vi.mock('../../src/utils/logger.js', () => ({
  log: { info: vi.fn(), debug: vi.fn(), warn: vi.fn(), error: vi.fn() },
}));

describe('access-control check', () => {
  it('exports accessControlCheck with correct interface', async () => {
    const { accessControlCheck } = await import('../../src/scanner/active/access-control.js');
    expect(accessControlCheck.name).toBe('access-control');
    expect(accessControlCheck.category).toBe('broken-access-control');
    expect(typeof accessControlCheck.run).toBe('function');
  });

  it('is not marked as parallel (sends requests)', async () => {
    const { accessControlCheck } = await import('../../src/scanner/active/access-control.js');
    expect(accessControlCheck.parallel).toBeUndefined();
  });
});

describe('identifyPrivilegedEndpoints', () => {
  it('identifies admin URLs', async () => {
    const { identifyPrivilegedEndpoints } = await import('../../src/scanner/active/access-control.js');
    const urls = [
      'http://localhost:3000/admin/users',
      'http://localhost:3000/api/products',
      'http://localhost:3000/dashboard',
      'http://localhost:3000/login',
      'http://localhost:3000/settings',
    ];
    const result = identifyPrivilegedEndpoints(urls);
    expect(result).toContain('http://localhost:3000/admin/users');
    expect(result).toContain('http://localhost:3000/dashboard');
    expect(result).toContain('http://localhost:3000/settings');
    expect(result).not.toContain('http://localhost:3000/login');
  });

  it('detects various admin patterns', async () => {
    const { identifyPrivilegedEndpoints } = await import('../../src/scanner/active/access-control.js');
    const patterns = [
      'http://example.com/manage/orders',
      'http://example.com/internal/api',
      'http://example.com/staff/list',
      'http://example.com/billing/invoices',
      'http://example.com/system/health',
      'http://example.com/control/panel',
    ];
    const result = identifyPrivilegedEndpoints(patterns);
    expect(result.length).toBe(patterns.length);
  });

  it('returns empty for non-privileged URLs', async () => {
    const { identifyPrivilegedEndpoints } = await import('../../src/scanner/active/access-control.js');
    const urls = [
      'http://localhost:3000/',
      'http://localhost:3000/login',
      'http://localhost:3000/signup',
      'http://localhost:3000/api/products',
      'http://localhost:3000/about',
    ];
    const result = identifyPrivilegedEndpoints(urls);
    expect(result).toEqual([]);
  });

  it('handles invalid URLs gracefully', async () => {
    const { identifyPrivilegedEndpoints } = await import('../../src/scanner/active/access-control.js');
    const urls = ['not-a-url', '', 'http://localhost:3000/admin'];
    const result = identifyPrivilegedEndpoints(urls);
    expect(result).toContain('http://localhost:3000/admin');
    expect(result.length).toBe(1);
  });

  it('is case-insensitive for pattern matching', async () => {
    const { identifyPrivilegedEndpoints } = await import('../../src/scanner/active/access-control.js');
    const urls = [
      'http://localhost:3000/Admin/panel',
      'http://localhost:3000/DASHBOARD',
      'http://localhost:3000/Settings/profile',
    ];
    const result = identifyPrivilegedEndpoints(urls);
    expect(result.length).toBe(3);
  });
});
