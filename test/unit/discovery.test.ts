import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { writeFileSync, unlinkSync, mkdtempSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { UrlFileLoader } from '../../src/scanner/discovery/url-file-loader.js';
import { NextJsExtractor } from '../../src/scanner/discovery/nextjs-extractor.js';
import { discoverRoutes } from '../../src/scanner/discovery/index.js';

// ─── UrlFileLoader ───────────────────────────────────────────────────

describe('UrlFileLoader', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'secbot-test-'));
  });

  it('loads URLs from a file', async () => {
    const filePath = join(tempDir, 'urls.txt');
    writeFileSync(filePath, 'https://example.com/page1\nhttps://example.com/page2\n');

    const loader = new UrlFileLoader(filePath);
    const routes = await loader.discover('https://example.com');

    expect(routes).toHaveLength(2);
    expect(routes[0]).toEqual({
      url: 'https://example.com/page1',
      source: 'file',
      confidence: 'high',
    });
    expect(routes[1]).toEqual({
      url: 'https://example.com/page2',
      source: 'file',
      confidence: 'high',
    });
  });

  it('skips comment lines starting with #', async () => {
    const filePath = join(tempDir, 'urls.txt');
    writeFileSync(
      filePath,
      '# This is a comment\nhttps://example.com/page1\n# Another comment\nhttps://example.com/page2\n',
    );

    const loader = new UrlFileLoader(filePath);
    const routes = await loader.discover('https://example.com');

    expect(routes).toHaveLength(2);
    expect(routes[0].url).toBe('https://example.com/page1');
    expect(routes[1].url).toBe('https://example.com/page2');
  });

  it('skips blank lines', async () => {
    const filePath = join(tempDir, 'urls.txt');
    writeFileSync(
      filePath,
      'https://example.com/page1\n\n\nhttps://example.com/page2\n\n',
    );

    const loader = new UrlFileLoader(filePath);
    const routes = await loader.discover('https://example.com');

    expect(routes).toHaveLength(2);
  });

  it('trims whitespace from lines', async () => {
    const filePath = join(tempDir, 'urls.txt');
    writeFileSync(
      filePath,
      '  https://example.com/page1  \n\thttps://example.com/page2\t\n',
    );

    const loader = new UrlFileLoader(filePath);
    const routes = await loader.discover('https://example.com');

    expect(routes).toHaveLength(2);
    expect(routes[0].url).toBe('https://example.com/page1');
    expect(routes[1].url).toBe('https://example.com/page2');
  });

  it('handles empty file', async () => {
    const filePath = join(tempDir, 'urls.txt');
    writeFileSync(filePath, '');

    const loader = new UrlFileLoader(filePath);
    const routes = await loader.discover('https://example.com');

    expect(routes).toHaveLength(0);
  });

  it('returns empty array for nonexistent file', async () => {
    const loader = new UrlFileLoader('/nonexistent/file.txt');
    const routes = await loader.discover('https://example.com');

    expect(routes).toHaveLength(0);
  });

  it('has name "file"', () => {
    const loader = new UrlFileLoader('/any/path.txt');
    expect(loader.name).toBe('file');
  });
});

// ─── NextJsExtractor ────────────────────────────────────────────────

describe('NextJsExtractor', () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('has name "nextjs"', () => {
    const extractor = new NextJsExtractor();
    expect(extractor.name).toBe('nextjs');
  });

  it('extracts URLs from sitemap.xml', async () => {
    const sitemapXml = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc></url>
  <url><loc>https://example.com/about</loc></url>
  <url><loc>https://example.com/contact</loc></url>
</urlset>`;

    globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.endsWith('/sitemap.xml')) {
        return new Response(sitemapXml, { status: 200 });
      }
      return new Response('', { status: 404 });
    });

    const extractor = new NextJsExtractor();
    const routes = await extractor.fetchSitemap('https://example.com');

    expect(routes).toHaveLength(3);
    expect(routes[0]).toEqual({
      url: 'https://example.com/',
      source: 'sitemap',
      confidence: 'high',
    });
    expect(routes[1].url).toBe('https://example.com/about');
    expect(routes[2].url).toBe('https://example.com/contact');
  });

  it('returns empty array when sitemap returns 404', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(new Response('', { status: 404 }));

    const extractor = new NextJsExtractor();
    const routes = await extractor.fetchSitemap('https://example.com');

    expect(routes).toHaveLength(0);
  });

  it('extracts routes from Next.js routes-manifest.json', async () => {
    const manifest = {
      staticRoutes: [
        { page: '/' },
        { page: '/about' },
        { page: '/pricing' },
      ],
      dynamicRoutes: [
        { page: '/blog/[slug]' },
      ],
    };

    globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('routes-manifest.json')) {
        return new Response(JSON.stringify(manifest), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response('', { status: 404 });
    });

    const extractor = new NextJsExtractor();
    const routes = await extractor.fetchManifest('https://example.com');

    expect(routes).toHaveLength(4);
    expect(routes[0]).toEqual({
      url: 'https://example.com/',
      source: 'nextjs',
      confidence: 'medium',
    });
    expect(routes[3].url).toBe('https://example.com/blog/[slug]');
  });

  it('extracts routes from build-manifest.json pages', async () => {
    const manifest = {
      pages: {
        '/': ['chunks/main.js'],
        '/about': ['chunks/about.js'],
        '/_app': ['chunks/app.js'], // should be skipped
        '/_document': ['chunks/doc.js'], // should be skipped
      },
    };

    globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.includes('build-manifest.json')) {
        return new Response(JSON.stringify(manifest), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response('', { status: 404 });
    });

    const extractor = new NextJsExtractor();
    const routes = await extractor.fetchManifest('https://example.com');

    expect(routes).toHaveLength(2);
    expect(routes.map((r) => r.url)).toEqual([
      'https://example.com/',
      'https://example.com/about',
    ]);
  });

  it('returns empty array when no manifests found', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue(new Response('', { status: 404 }));

    const extractor = new NextJsExtractor();
    const routes = await extractor.fetchManifest('https://example.com');

    expect(routes).toHaveLength(0);
  });

  it('probes common paths and returns accessible ones', async () => {
    globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.endsWith('/login')) {
        return new Response('', { status: 200 });
      }
      if (url.endsWith('/admin')) {
        return new Response('', { status: 403 });
      }
      if (url.endsWith('/api/health')) {
        return new Response('', { status: 200 });
      }
      return new Response('', { status: 404 });
    });

    const extractor = new NextJsExtractor();
    const routes = await extractor.probeCommonPaths('https://example.com');

    expect(routes.length).toBeGreaterThanOrEqual(3);
    const urls = routes.map((r) => r.url);
    expect(urls).toContain('https://example.com/login');
    expect(urls).toContain('https://example.com/admin');
    expect(urls).toContain('https://example.com/api/health');

    for (const route of routes) {
      expect(route.source).toBe('probe');
      expect(route.confidence).toBe('low');
    }
  });

  it('handles fetch errors gracefully in probing', async () => {
    globalThis.fetch = vi.fn().mockRejectedValue(new Error('Network error'));

    const extractor = new NextJsExtractor();
    const routes = await extractor.probeCommonPaths('https://example.com');

    expect(routes).toHaveLength(0);
  });
});

// ─── discoverRoutes orchestrator ─────────────────────────────────────

describe('discoverRoutes', () => {
  const originalFetch = globalThis.fetch;
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'secbot-test-'));
    // Mock fetch to return 404 for all requests (skip NextJsExtractor network calls)
    globalThis.fetch = vi.fn().mockResolvedValue(new Response('', { status: 404 }));
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it('deduplicates routes across discoverers', async () => {
    // Write a URL file that contains a URL that will also come from probing
    const filePath = join(tempDir, 'urls.txt');
    writeFileSync(filePath, 'https://example.com/login\nhttps://example.com/custom\n');

    // Mock fetch: /login returns 200 (probe will also find it)
    globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.endsWith('/login')) {
        return new Response('', { status: 200 });
      }
      return new Response('', { status: 404 });
    });

    const routes = await discoverRoutes('https://example.com', filePath);

    // /login should appear only once (from probe or file, but deduplicated)
    const loginRoutes = routes.filter((r) => r.url === 'https://example.com/login');
    expect(loginRoutes).toHaveLength(1);

    // /custom should appear once (from file only)
    const customRoutes = routes.filter((r) => r.url === 'https://example.com/custom');
    expect(customRoutes).toHaveLength(1);
  });

  it('returns routes from URL file when provided', async () => {
    const filePath = join(tempDir, 'urls.txt');
    writeFileSync(filePath, 'https://example.com/a\nhttps://example.com/b\n');

    const routes = await discoverRoutes('https://example.com', filePath);

    const fileRoutes = routes.filter((r) => r.source === 'file');
    expect(fileRoutes).toHaveLength(2);
  });

  it('works without URL file', async () => {
    const routes = await discoverRoutes('https://example.com');
    // Should not throw, may return 0 or some routes from probing
    expect(Array.isArray(routes)).toBe(true);
  });

  it('preserves first occurrence when deduplicating', async () => {
    const filePath = join(tempDir, 'urls.txt');
    // This URL will be found by probing first (nextjs extractor runs first)
    writeFileSync(filePath, 'https://example.com/api/health\n');

    globalThis.fetch = vi.fn().mockImplementation(async (url: string) => {
      if (url.endsWith('/api/health')) {
        return new Response('', { status: 200 });
      }
      return new Response('', { status: 404 });
    });

    const routes = await discoverRoutes('https://example.com', filePath);

    const healthRoutes = routes.filter((r) => r.url === 'https://example.com/api/health');
    expect(healthRoutes).toHaveLength(1);
    // First discoverer (nextjs/probe) should win
    expect(healthRoutes[0].source).toBe('probe');
  });
});
