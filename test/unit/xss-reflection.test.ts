import { describe, it, expect } from 'vitest';
import { checkDangerousReflection, isHtmlEncoded, checkJsStringBreakout } from '../../src/scanner/active/xss.js';

describe('isHtmlEncoded', () => {
  it('returns true when HTML entities are near the marker', () => {
    const content = 'Hello &lt;script&gt;secbot-xss-123&lt;/script&gt;';
    expect(isHtmlEncoded(content, 'secbot-xss-123')).toBe(true);
  });

  it('returns false when no HTML entities are near the marker', () => {
    const content = '<div>secbot-xss-123</div>';
    expect(isHtmlEncoded(content, 'secbot-xss-123')).toBe(false);
  });

  it('returns false when marker is not found', () => {
    expect(isHtmlEncoded('no marker here', 'secbot-xss-123')).toBe(false);
  });

  it('detects &amp; entity', () => {
    const content = 'value=secbot-xss-123&amp;other=1';
    expect(isHtmlEncoded(content, 'secbot-xss-123')).toBe(true);
  });

  it('detects &#39; entity', () => {
    const content = "data-val=&#39;secbot-xss-123&#39;";
    expect(isHtmlEncoded(content, 'secbot-xss-123')).toBe(true);
  });
});

describe('checkDangerousReflection', () => {
  const MARKER = 'secbot-xss-abc123';
  const PAYLOAD_SCRIPT = '<script>alert(1)</script>';
  const PAYLOAD_IMG = '<img src=x onerror=alert(1)>';
  const PAYLOAD_ENCODED = '%3Cscript%3Ealert(1)%3C/script%3E';

  describe('safe cases — should return null', () => {
    it('returns null when neither payload nor marker is present', () => {
      expect(checkDangerousReflection('Hello world', PAYLOAD_SCRIPT, MARKER)).toBeNull();
    });

    it('returns null when marker is HTML-encoded (app sanitizes output)', () => {
      const content = `<p>&lt;b&gt;${MARKER}&lt;/b&gt;</p>`;
      expect(checkDangerousReflection(content, PAYLOAD_SCRIPT, MARKER)).toBeNull();
    });

    it('returns null when marker only appears inside <script> blocks (Next.js RSC)', () => {
      const content = `
        <html><body>
          <div id="app">Clean content</div>
          <script>self.__next_f.push([1,"searchParams":{"q":"${MARKER}"}])</script>
        </body></html>`;
      expect(checkDangerousReflection(content, PAYLOAD_SCRIPT, MARKER)).toBeNull();
    });

    it('returns null when marker in __NEXT_DATA__ script block', () => {
      const content = `
        <html><body>
          <p>Page content</p>
          <script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"q":"${MARKER}"}}}</script>
        </body></html>`;
      expect(checkDangerousReflection(content, PAYLOAD_SCRIPT, MARKER)).toBeNull();
    });

    it('returns null when URL-encoded payload only appears inside script blocks', () => {
      // URL-encoded payloads can't close script tags, so even if reflected in RSC data, safe
      const content = `
        <html><body>
          <div>Clean</div>
          <script>self.__next_f.push([1,"data":"${PAYLOAD_ENCODED}"])</script>
        </body></html>`;
      expect(checkDangerousReflection(content, PAYLOAD_ENCODED, MARKER)).toBeNull();
    });

    it('returns null when marker appears in plain text body (not dangerous context)', () => {
      const content = `<html><body><p>You searched for: ${MARKER}</p></body></html>`;
      expect(checkDangerousReflection(content, PAYLOAD_SCRIPT, MARKER)).toBeNull();
    });

    it('returns null for marker in multiple script blocks but nowhere else', () => {
      const content = `
        <html><body>
          <script>var a = "${MARKER}";</script>
          <script>var b = {"q": "${MARKER}"};</script>
          <div>No marker here</div>
        </body></html>`;
      expect(checkDangerousReflection(content, PAYLOAD_SCRIPT, MARKER)).toBeNull();
    });
  });

  describe('dangerous cases — should return context string', () => {
    it('detects raw <script> payload reflected outside script blocks', () => {
      const content = `<html><body><div>${PAYLOAD_SCRIPT}</div></body></html>`;
      const result = checkDangerousReflection(content, PAYLOAD_SCRIPT, MARKER);
      expect(result).not.toBeNull();
    });

    it('detects payload reflected inside existing event handler', () => {
      // Payload appears directly inside event handler value (no nested quotes)
      const payload = 'alert-secbot-1';
      const content = `<html><body><div onclick="doSomething(${payload})">test</div></body></html>`;
      const result = checkDangerousReflection(content, payload, MARKER);
      expect(result).not.toBeNull();
    });

    it('detects payload reflected inside existing javascript: href', () => {
      // Payload appears inside a pre-existing javascript: URI
      const payload = 'alert(document.cookie)';
      const content = `<a href="javascript:void(${payload})">click</a>`;
      const result = checkDangerousReflection(content, payload, MARKER);
      expect(result).not.toBeNull();
    });

    it('detects marker reflected in event handler outside scripts', () => {
      const content = `<html><body><div onload="${MARKER}">test</div></body></html>`;
      const result = checkDangerousReflection(content, PAYLOAD_SCRIPT, MARKER);
      expect(result).not.toBeNull();
    });

    it('detects marker in unquoted attribute value', () => {
      const content = `<html><body><input value=${MARKER}></body></html>`;
      const result = checkDangerousReflection(content, PAYLOAD_SCRIPT, MARKER);
      expect(result).not.toBeNull();
    });

    it('detects marker in template expression {{}}', () => {
      const content = `<html><body><div>{{${MARKER}}}</div></body></html>`;
      const result = checkDangerousReflection(content, PAYLOAD_SCRIPT, MARKER);
      expect(result).not.toBeNull();
    });

    it('detects marker in template expression ${}', () => {
      const content = `<html><body><div>\${${MARKER}}</div></body></html>`;
      const result = checkDangerousReflection(content, PAYLOAD_SCRIPT, MARKER);
      expect(result).not.toBeNull();
    });

    it('detects raw HTML payload even when also in script blocks', () => {
      // Raw HTML payload (<script>) CAN close outer script tags, so must check full content
      const content = `
        <html><body>
          <script>var data = "${PAYLOAD_SCRIPT}";</script>
          <div>${PAYLOAD_SCRIPT}</div>
        </body></html>`;
      const result = checkDangerousReflection(content, PAYLOAD_SCRIPT, MARKER);
      expect(result).not.toBeNull();
    });

    it('detects attribute break-out pattern', () => {
      const payload = '"><img src=x onerror=alert(1)>';
      const content = `<input type="text" value="${payload}">`;
      // The payload contains `"` which breaks out of the attribute
      const result = checkDangerousReflection(content, payload, MARKER);
      expect(result).not.toBeNull();
    });
  });

  describe('Next.js RSC false positive regression', () => {
    it('does NOT flag URL-encoded marker in RSC self.__next_f.push data', () => {
      const encodedMarker = encodeURIComponent(MARKER);
      const content = `
        <html><body>
          <div id="__next">App content</div>
          <script>self.__next_f.push([1,"3:[\\"$\\",\\"$L4\\",null,{\\"searchParams\\":{\\"q\\":\\"${encodedMarker}\\"}}]"])</script>
          <script>self.__next_f.push([1,"5:[\\"$\\",\\"main\\",null,{\\"children\\":\\"Results for ${encodedMarker}\\"}]"])</script>
        </body></html>`;
      expect(checkDangerousReflection(content, PAYLOAD_SCRIPT, MARKER)).toBeNull();
    });

    it('does NOT flag plain marker in RSC route metadata', () => {
      const content = `
        <html><body>
          <div id="__next"><h1>Search</h1></div>
          <script>self.__next_f.push([1,"route:\\"/(search)\\",params:{\\"q\\":\\"${MARKER}\\"}"])</script>
        </body></html>`;
      expect(checkDangerousReflection(content, PAYLOAD_SCRIPT, MARKER)).toBeNull();
    });

    it('does NOT flag URL-encoded payload (%3Cscript%3E) in RSC data', () => {
      const urlEncPayload = '%3Cscript%3Ealert(1)%3C%2Fscript%3E';
      const content = `
        <html><body>
          <div id="__next">Clean</div>
          <script>self.__next_f.push([1,"q=${urlEncPayload}"])</script>
        </body></html>`;
      expect(checkDangerousReflection(content, urlEncPayload, MARKER)).toBeNull();
    });

    it('DOES flag marker if it also appears outside script blocks', () => {
      // Marker in both RSC data AND in the rendered DOM → dangerous
      const content = `
        <html><body>
          <div id="__next"><input value=${MARKER}></div>
          <script>self.__next_f.push([1,"q=${MARKER}"])</script>
        </body></html>`;
      const result = checkDangerousReflection(content, PAYLOAD_SCRIPT, MARKER);
      expect(result).not.toBeNull();
    });
  });

  describe('edge cases', () => {
    it('handles empty marker gracefully', () => {
      const content = '<div>test</div>';
      expect(checkDangerousReflection(content, PAYLOAD_SCRIPT, '')).toBeNull();
    });

    it('handles content with many script blocks', () => {
      let content = '<html><body>';
      for (let i = 0; i < 10; i++) {
        content += `<script>var v${i} = "${MARKER}";</script>`;
      }
      content += '<div>safe content</div></body></html>';
      expect(checkDangerousReflection(content, PAYLOAD_SCRIPT, MARKER)).toBeNull();
    });

    it('handles nested script-like content in attributes', () => {
      // A data attribute with "script" in its value should NOT be stripped
      const content = `<div data-info="script-tag" title="${MARKER}">safe</div>`;
      // Marker appears outside actual <script> blocks, but not in dangerous context
      expect(checkDangerousReflection(content, PAYLOAD_SCRIPT, MARKER)).toBeNull();
    });

    it('raw HTML payload (<img>) reflected as-is is dangerous', () => {
      const payload = '<img src=x onerror=alert(1)>';
      const content = `<html><body><div>Result: ${payload}</div></body></html>`;
      const result = checkDangerousReflection(content, payload, MARKER);
      expect(result).not.toBeNull();
    });
  });

  describe('JS string context via checkDangerousReflection', () => {
    it('detects JS string breakout when payload only appears in script block', () => {
      const jsPayload = '";alert("secbot-xss-51");//';
      const jsMarker = 'secbot-xss-51';
      const content = `<html><body>
        <div>Clean content</div>
        <script>var search = "${jsPayload}";</script>
      </body></html>`;
      const result = checkDangerousReflection(content, jsPayload, jsMarker);
      expect(result).not.toBeNull();
      expect(result).toContain('JS string breakout');
    });

    it('returns null for JS-context payload when server escapes quotes', () => {
      const jsPayload = '";alert("secbot-xss-51");//';
      const jsMarker = 'secbot-xss-51';
      const escaped = jsPayload.replace(/"/g, '\\"');
      const content = `<html><body>
        <script>var search = "${escaped}";</script>
      </body></html>`;
      const result = checkDangerousReflection(content, jsPayload, jsMarker);
      expect(result).toBeNull();
    });

    it('does NOT flag JS-context payload in properly encoded body text', () => {
      // Browser decodes &quot; in text content → raw " appears, but this is safe
      // because the payload has no HTML tags to create new elements
      const jsPayload = '";alert("secbot-xss-51");//';
      const jsMarker = 'secbot-xss-51';
      // Simulate browser-rendered text content (entities decoded)
      const content = `<html><body>
        <h1>Search Results for: ${jsPayload}</h1>
        <p>No results found for ${jsPayload}</p>
      </body></html>`;
      const result = checkDangerousReflection(content, jsPayload, jsMarker);
      expect(result).toBeNull();
    });
  });
});
