/** XSS test payloads — non-destructive detection only */
export const XSS_PAYLOADS = [
  // Basic script injection
  '<script>alert("secbot-xss-1")</script>',
  '"><script>alert("secbot-xss-2")</script>',
  "'><script>alert('secbot-xss-3')</script>",

  // Event handler injection
  '" onmouseover="alert(\'secbot-xss-4\')"',
  "' onmouseover='alert(\"secbot-xss-5\")'",
  '" onfocus="alert(\'secbot-xss-6\')" autofocus="',

  // IMG tag injection
  '<img src=x onerror="alert(\'secbot-xss-7\')">',
  '"><img src=x onerror="alert(\'secbot-xss-8\')">',

  // SVG injection
  '<svg onload="alert(\'secbot-xss-9\')">',

  // Template literal injection
  '${alert("secbot-xss-10")}',
  '{{constructor.constructor("alert(1)")()}}',
];

/** XSS detection markers to search for in responses */
export const XSS_MARKERS = [
  'secbot-xss-1',
  'secbot-xss-2',
  'secbot-xss-3',
  'secbot-xss-4',
  'secbot-xss-5',
  'secbot-xss-6',
  'secbot-xss-7',
  'secbot-xss-8',
  'secbot-xss-9',
  'secbot-xss-10',
];
