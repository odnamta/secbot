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
];

// Control payloads for validation (confirm template evaluation, not just string matching)
// Use large numbers so the expected output never appears naturally in web content
export const SSTI_CONTROL_PAYLOADS: SSTIPayload[] = [
  { payload: '{{71829+71829}}', expected: '143658', engine: 'Jinja2/Twig' },
  { payload: '${71829+71829}', expected: '143658', engine: 'Freemarker/Velocity' },
  { payload: '<%= 71829+71829 %>', expected: '143658', engine: 'ERB/EJS' },
];
