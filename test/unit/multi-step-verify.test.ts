import { describe, it, expect } from 'vitest';
import { detectContext, type InjectedMarker, type PersistenceHit } from '../../src/utils/multi-step-verify.js';

describe('detectContext', () => {
  it('returns html-body for marker in plain body text', () => {
    const html = '<html><body><p>Hello secbot-marker-123 world</p></body></html>';
    expect(detectContext(html, 'secbot-marker-123')).toBe('html-body');
  });

  it('returns script when marker is inside a <script> block', () => {
    const html = '<html><body><script>var x = "secbot-marker-abc";</script></body></html>';
    expect(detectContext(html, 'secbot-marker-abc')).toBe('script');
  });

  it('returns script for inline script with attributes', () => {
    const html = '<html><script type="text/javascript">console.log("secbot-marker-xyz")</script></html>';
    expect(detectContext(html, 'secbot-marker-xyz')).toBe('script');
  });

  it('returns attribute when marker is inside an attribute value', () => {
    const html = '<html><body><input value="secbot-marker-attr" name="field"></body></html>';
    expect(detectContext(html, 'secbot-marker-attr')).toBe('attribute');
  });

  it('returns attribute for double-quoted attribute', () => {
    const html = '<html><a href="https://example.com/secbot-marker-href">link</a></html>';
    expect(detectContext(html, 'secbot-marker-href')).toBe('attribute');
  });

  it('returns attribute for single-quoted attribute', () => {
    const html = "<html><div data-value='secbot-marker-sq'>x</div></html>";
    expect(detectContext(html, 'secbot-marker-sq')).toBe('attribute');
  });

  it('returns html-body when marker is after a closed script tag', () => {
    const html = '<script>var a=1;</script><p>secbot-marker-after</p>';
    expect(detectContext(html, 'secbot-marker-after')).toBe('html-body');
  });

  it('returns unknown when marker is not found', () => {
    const html = '<html><body>nothing here</body></html>';
    expect(detectContext(html, 'secbot-missing')).toBe('unknown');
  });

  it('handles marker at the very start of the document', () => {
    const html = 'secbot-marker-start<html><body></body></html>';
    expect(detectContext(html, 'secbot-marker-start')).toBe('html-body');
  });

  it('handles long content before the marker without crashing', () => {
    const padding = 'x'.repeat(500);
    const html = `<html><body>${padding}<p>secbot-marker-deep</p></body></html>`;
    expect(detectContext(html, 'secbot-marker-deep')).toBe('html-body');
  });
});

describe('InjectedMarker type', () => {
  it('accepts valid POST marker', () => {
    const marker: InjectedMarker = {
      marker: 'secbot-sxss-abc12345',
      payload: '<img src=x onerror=alert(1)>',
      injectionUrl: 'https://example.com/profile',
      injectionField: 'bio',
      injectionMethod: 'POST',
    };
    expect(marker.marker).toBe('secbot-sxss-abc12345');
    expect(marker.injectionMethod).toBe('POST');
  });

  it('accepts valid PUT marker', () => {
    const marker: InjectedMarker = {
      marker: 'secbot-sxss-def67890',
      payload: '<script>alert(1)</script>',
      injectionUrl: 'https://example.com/api/user',
      injectionField: 'name',
      injectionMethod: 'PUT',
    };
    expect(marker.injectionMethod).toBe('PUT');
  });

  it('accepts valid PATCH marker', () => {
    const marker: InjectedMarker = {
      marker: 'secbot-sxss-ghi11111',
      payload: '{{constructor.constructor("alert(1)")()}}',
      injectionUrl: 'https://example.com/api/settings',
      injectionField: 'displayName',
      injectionMethod: 'PATCH',
    };
    expect(marker.injectionMethod).toBe('PATCH');
  });
});

describe('PersistenceHit type', () => {
  it('accepts valid hit structure', () => {
    const hit: PersistenceHit = {
      marker: 'secbot-sxss-abc12345',
      foundOnUrl: 'https://example.com/admin/users',
      injectionUrl: 'https://example.com/profile',
      injectionField: 'bio',
      context: 'html-body',
    };
    expect(hit.foundOnUrl).not.toBe(hit.injectionUrl);
    expect(hit.context).toBe('html-body');
  });

  it('supports all context types', () => {
    const contexts: PersistenceHit['context'][] = ['html-body', 'attribute', 'script', 'unknown'];
    for (const ctx of contexts) {
      const hit: PersistenceHit = {
        marker: 'test',
        foundOnUrl: 'https://a.com/page',
        injectionUrl: 'https://a.com/form',
        injectionField: 'field',
        context: ctx,
      };
      expect(hit.context).toBe(ctx);
    }
  });
});

describe('checkPersistence (edge cases without Playwright)', () => {
  // We test the function signature / early-return logic by importing it.
  // Actual browser tests belong in integration tests.
  it('returns empty array for no markers', async () => {
    const { checkPersistence } = await import('../../src/utils/multi-step-verify.js');
    // Pass null-ish context — the function should return early before using it
    const result = await checkPersistence(
      {} as any, // unused because markers is empty
      [],
      ['https://example.com/page1'],
    );
    expect(result).toEqual([]);
  });

  it('returns empty array for no URLs', async () => {
    const { checkPersistence } = await import('../../src/utils/multi-step-verify.js');
    const markers: InjectedMarker[] = [
      {
        marker: 'secbot-test-1',
        payload: '<img src=x>',
        injectionUrl: 'https://example.com/form',
        injectionField: 'name',
        injectionMethod: 'POST',
      },
    ];
    const result = await checkPersistence(
      {} as any, // unused because urlsToCheck is empty
      markers,
      [],
    );
    expect(result).toEqual([]);
  });
});
