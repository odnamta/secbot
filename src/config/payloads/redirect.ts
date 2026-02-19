/** Open redirect test payloads */
export const REDIRECT_PAYLOADS = [
  'https://evil.example.com',
  '//evil.example.com',
  '/\\evil.example.com',
  'https://evil.example.com%00.legitimate.com',
  '////evil.example.com',
];
