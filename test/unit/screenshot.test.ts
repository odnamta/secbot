import { describe, it, expect, vi, beforeEach } from 'vitest';
import { mkdtempSync, existsSync, unlinkSync, rmdirSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { captureScreenshot, captureScreenshotOnFinding } from '../../src/scanner/screenshot.js';
import type { RawFinding } from '../../src/scanner/types.js';

// Mock Page object
function mockPage(opts: { screenshotFail?: boolean } = {}) {
  return {
    screenshot: opts.screenshotFail
      ? vi.fn().mockRejectedValue(new Error('Screenshot failed'))
      : vi.fn().mockResolvedValue(Buffer.from('fake-png-data')),
    goto: vi.fn().mockResolvedValue(null),
    close: vi.fn().mockResolvedValue(undefined),
  };
}

// Mock BrowserContext object
function mockContext(opts: { screenshotFail?: boolean; gotoFail?: boolean } = {}) {
  const page = mockPage(opts);
  if (opts.gotoFail) {
    page.goto = vi.fn().mockRejectedValue(new Error('Navigation failed'));
  }
  return {
    context: {
      newPage: vi.fn().mockResolvedValue(page),
    },
    page,
  };
}

function makeFinding(overrides: Partial<RawFinding> = {}): RawFinding {
  return {
    id: 'test-finding-001',
    category: 'xss',
    severity: 'high',
    title: 'Reflected XSS',
    description: 'User input reflected in response',
    url: 'https://example.com/search?q=test',
    evidence: '<script>alert(1)</script>',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

describe('screenshot', () => {
  let tmpDir: string;

  beforeEach(() => {
    tmpDir = mkdtempSync(join(tmpdir(), 'secbot-screenshot-test-'));
  });

  describe('captureScreenshot', () => {
    it('calls page.screenshot with the correct path and fullPage option', async () => {
      const page = mockPage();
      const outPath = join(tmpDir, 'test-screenshot.png');

      await captureScreenshot(page as any, outPath);

      expect(page.screenshot).toHaveBeenCalledWith({
        path: outPath,
        fullPage: true,
      });
    });

    it('returns the output path', async () => {
      const page = mockPage();
      const outPath = join(tmpDir, 'test-screenshot.png');

      const result = await captureScreenshot(page as any, outPath);
      expect(result).toBe(outPath);
    });

    it('creates parent directories if needed', async () => {
      const page = mockPage();
      const deepPath = join(tmpDir, 'sub', 'dir', 'screenshot.png');

      await captureScreenshot(page as any, deepPath);

      expect(page.screenshot).toHaveBeenCalledWith({
        path: deepPath,
        fullPage: true,
      });
    });

    it('propagates errors from page.screenshot', async () => {
      const page = mockPage({ screenshotFail: true });
      const outPath = join(tmpDir, 'fail.png');

      await expect(captureScreenshot(page as any, outPath)).rejects.toThrow('Screenshot failed');
    });
  });

  describe('captureScreenshotOnFinding', () => {
    it('navigates to finding URL and captures screenshot', async () => {
      const { context, page } = mockContext();
      const finding = makeFinding();

      const result = await captureScreenshotOnFinding(context as any, finding, tmpDir);

      expect(page.goto).toHaveBeenCalledWith(finding.url, {
        waitUntil: 'networkidle',
        timeout: 15000,
      });
      expect(page.screenshot).toHaveBeenCalled();
      expect(result).toContain('finding-test-finding-001.png');
    });

    it('returns null when navigation fails', async () => {
      const { context } = mockContext({ gotoFail: true });
      const finding = makeFinding();

      const result = await captureScreenshotOnFinding(context as any, finding, tmpDir);
      expect(result).toBeNull();
    });

    it('returns null when screenshot fails', async () => {
      const { context } = mockContext({ screenshotFail: true });
      const finding = makeFinding();

      const result = await captureScreenshotOnFinding(context as any, finding, tmpDir);
      expect(result).toBeNull();
    });

    it('sanitizes finding ID for filename', async () => {
      const { context, page } = mockContext();
      const finding = makeFinding({ id: 'finding/with:special.chars' });

      const result = await captureScreenshotOnFinding(context as any, finding, tmpDir);

      expect(result).toContain('finding-finding_with_special_chars.png');
    });

    it('always closes the page, even on error', async () => {
      const { context, page } = mockContext({ gotoFail: true });
      const finding = makeFinding();

      await captureScreenshotOnFinding(context as any, finding, tmpDir);

      expect(page.close).toHaveBeenCalled();
    });
  });
});
