export interface SSTIPayload {
  payload: string;
  expected: string;
  engine: string;
}

export const SSTI_PAYLOADS: SSTIPayload[] = [
  { payload: '{{7*7}}', expected: '49', engine: 'Jinja2/Twig' },
  { payload: '${7*7}', expected: '49', engine: 'Freemarker/Velocity' },
  { payload: '<%= 7*7 %>', expected: '49', engine: 'ERB/EJS' },
  { payload: '#{7*7}', expected: '49', engine: 'Pug/Slim' },
  { payload: "{{7*'7'}}", expected: '7777777', engine: 'Jinja2 (string mul)' },
  { payload: '@(7*7)', expected: '49', engine: 'Razor' },
];

// Control payloads for validation (confirm template evaluation, not just string matching)
export const SSTI_CONTROL_PAYLOADS: SSTIPayload[] = [
  { payload: '{{7+7}}', expected: '14', engine: 'Jinja2/Twig' },
  { payload: '${7+7}', expected: '14', engine: 'Freemarker/Velocity' },
  { payload: '<%= 7+7 %>', expected: '14', engine: 'ERB/EJS' },
];
