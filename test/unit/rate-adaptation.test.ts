import { describe, it, expect } from 'vitest';
import { RateLimiter, isCaptchaResponse } from '../../src/utils/rate-limiter.js';

describe('CAPTCHA detection', () => {
  it('detects Google reCAPTCHA', () => {
    expect(isCaptchaResponse('<div class="g-recaptcha" data-sitekey="abc"></div>')).toBe(true);
  });

  it('detects hCaptcha', () => {
    expect(isCaptchaResponse('<div class="h-captcha" data-sitekey="xyz"></div>')).toBe(true);
  });

  it('detects Cloudflare Turnstile', () => {
    expect(isCaptchaResponse('<div class="cf-turnstile"></div>')).toBe(true);
  });

  it('detects generic captcha container', () => {
    expect(isCaptchaResponse('<div id="captcha-container">Solve the captcha</div>')).toBe(true);
  });

  it('detects data-sitekey attribute', () => {
    expect(isCaptchaResponse('<div data-sitekey="6LdXXX"></div>')).toBe(true);
  });

  it('detects captcha script src', () => {
    expect(isCaptchaResponse('<script src="https://www.google.com/recaptcha/api.js"></script>')).toBe(true);
  });

  it('detects Cloudflare challenges URL', () => {
    expect(isCaptchaResponse('<iframe src="https://challenges.cloudflare.com/..."></iframe>')).toBe(true);
  });

  it('returns false for normal page', () => {
    expect(isCaptchaResponse('<html><body><h1>Hello World</h1></body></html>')).toBe(false);
  });

  it('returns false for empty body', () => {
    expect(isCaptchaResponse('')).toBe(false);
  });

  it('is case-insensitive', () => {
    expect(isCaptchaResponse('<div class="G-RECAPTCHA"></div>')).toBe(true);
  });
});

describe('RateLimiter CAPTCHA handling', () => {
  it('recordCaptcha increases delay aggressively', () => {
    const limiter = new RateLimiter({ requestsPerSecond: 10, initialDelayMs: 100 });
    const before = limiter.getStats().currentDelayMs;
    limiter.recordCaptcha();
    const after = limiter.getStats().currentDelayMs;
    expect(after).toBeGreaterThan(before);
    // Should be 4x (backoffMultiplier=2, recordCaptcha uses 2*multiplier)
    expect(after).toBe(before * 4);
  });

  it('recordCaptcha increments backoff counter', () => {
    const limiter = new RateLimiter({ requestsPerSecond: 10, initialDelayMs: 100 });
    expect(limiter.getStats().backoffs).toBe(0);
    limiter.recordCaptcha();
    expect(limiter.getStats().backoffs).toBe(1);
  });

  it('recordCaptcha respects maxDelay', () => {
    const limiter = new RateLimiter({ initialDelayMs: 10000, maxDelayMs: 30000 });
    limiter.recordCaptcha();
    expect(limiter.getStats().currentDelayMs).toBeLessThanOrEqual(30000);
  });

  it('multiple CAPTCHAs compound the backoff', () => {
    const limiter = new RateLimiter({ requestsPerSecond: 10, initialDelayMs: 100 });
    limiter.recordCaptcha(); // 100 * 4 = 400
    limiter.recordCaptcha(); // 400 * 4 = 1600
    expect(limiter.getStats().currentDelayMs).toBe(1600);
  });

  it('recovery after CAPTCHA backoff with 2xx responses', () => {
    const limiter = new RateLimiter({ requestsPerSecond: 10, initialDelayMs: 100 });
    limiter.recordCaptcha(); // 400ms
    // 5 consecutive 2xx → halve delay
    for (let i = 0; i < 5; i++) limiter.recordResponse(200);
    expect(limiter.getStats().currentDelayMs).toBe(200); // 400 / 2
  });
});
