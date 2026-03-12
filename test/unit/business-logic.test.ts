import { describe, it, expect, vi } from 'vitest';
import {
  businessLogicCheck,
  isBusinessUrl,
  hasBusinessFields,
  getPriceFields,
  getQuantityFields,
  hasStepParam,
  extractStepParam,
  filterBusinessForms,
  filterBusinessApiEndpoints,
  BUSINESS_URL_PATTERNS,
  PRICE_FIELD_PATTERNS,
  QUANTITY_FIELD_PATTERNS,
  COUPON_FIELD_PATTERNS,
  BUSINESS_FIELD_PATTERNS,
  PRICE_PAYLOADS,
  QUANTITY_PAYLOADS,
  STEP_PARAM_PATTERNS,
} from '../../src/scanner/active/business-logic.js';
import type { FormInfo } from '../../src/scanner/types.js';

// Mock the logger
vi.mock('../../src/utils/logger.js', () => ({
  log: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

describe('Business Logic Vulnerability Detection — Unit Tests', () => {
  describe('metadata', () => {
    it('has correct name', () => {
      expect(businessLogicCheck.name).toBe('business-logic');
    });

    it('has correct category', () => {
      expect(businessLogicCheck.category).toBe('business-logic');
    });

    it('does not have parallel flag', () => {
      expect(businessLogicCheck.parallel).toBeUndefined();
    });

    it('has a run function', () => {
      expect(typeof businessLogicCheck.run).toBe('function');
    });
  });

  describe('isBusinessUrl()', () => {
    it('detects /cart URL', () => {
      expect(isBusinessUrl('https://shop.example.com/cart')).toBe(true);
    });

    it('detects /checkout URL', () => {
      expect(isBusinessUrl('https://shop.example.com/checkout')).toBe(true);
    });

    it('detects /payment URL', () => {
      expect(isBusinessUrl('https://shop.example.com/payment/process')).toBe(true);
    });

    it('detects /order URL', () => {
      expect(isBusinessUrl('https://shop.example.com/order/123')).toBe(true);
    });

    it('detects /purchase URL', () => {
      expect(isBusinessUrl('https://shop.example.com/purchase')).toBe(true);
    });

    it('detects /basket URL', () => {
      expect(isBusinessUrl('https://shop.example.com/basket')).toBe(true);
    });

    it('detects /billing URL', () => {
      expect(isBusinessUrl('https://shop.example.com/billing')).toBe(true);
    });

    it('is case-insensitive', () => {
      expect(isBusinessUrl('https://shop.example.com/CHECKOUT')).toBe(true);
      expect(isBusinessUrl('https://shop.example.com/Cart')).toBe(true);
    });

    it('returns false for non-business URLs', () => {
      expect(isBusinessUrl('https://example.com/about')).toBe(false);
      expect(isBusinessUrl('https://example.com/contact')).toBe(false);
      expect(isBusinessUrl('https://example.com/blog')).toBe(false);
    });

    it('returns false for invalid URLs', () => {
      expect(isBusinessUrl('not-a-url')).toBe(false);
    });
  });

  describe('hasBusinessFields()', () => {
    it('detects price field', () => {
      const form: FormInfo = {
        action: '/submit',
        method: 'POST',
        inputs: [{ name: 'price', type: 'text' }],
        pageUrl: 'https://example.com',
      };
      expect(hasBusinessFields(form)).toBe(true);
    });

    it('detects quantity field', () => {
      const form: FormInfo = {
        action: '/submit',
        method: 'POST',
        inputs: [{ name: 'qty', type: 'number' }],
        pageUrl: 'https://example.com',
      };
      expect(hasBusinessFields(form)).toBe(true);
    });

    it('detects coupon field', () => {
      const form: FormInfo = {
        action: '/submit',
        method: 'POST',
        inputs: [{ name: 'coupon', type: 'text' }],
        pageUrl: 'https://example.com',
      };
      expect(hasBusinessFields(form)).toBe(true);
    });

    it('detects discount field', () => {
      const form: FormInfo = {
        action: '/submit',
        method: 'POST',
        inputs: [{ name: 'discount', type: 'hidden' }],
        pageUrl: 'https://example.com',
      };
      expect(hasBusinessFields(form)).toBe(true);
    });

    it('returns false for non-business fields', () => {
      const form: FormInfo = {
        action: '/submit',
        method: 'POST',
        inputs: [
          { name: 'username', type: 'text' },
          { name: 'password', type: 'password' },
          { name: 'email', type: 'email' },
        ],
        pageUrl: 'https://example.com',
      };
      expect(hasBusinessFields(form)).toBe(false);
    });

    it('returns false for empty inputs', () => {
      const form: FormInfo = {
        action: '/submit',
        method: 'POST',
        inputs: [],
        pageUrl: 'https://example.com',
      };
      expect(hasBusinessFields(form)).toBe(false);
    });
  });

  describe('getPriceFields()', () => {
    it('extracts price-related field names', () => {
      const form: FormInfo = {
        action: '/submit',
        method: 'POST',
        inputs: [
          { name: 'price', type: 'text' },
          { name: 'amount', type: 'hidden' },
          { name: 'username', type: 'text' },
          { name: 'total', type: 'text' },
        ],
        pageUrl: 'https://example.com',
      };
      const fields = getPriceFields(form);
      expect(fields).toContain('price');
      expect(fields).toContain('amount');
      expect(fields).toContain('total');
      expect(fields).not.toContain('username');
    });

    it('returns empty array when no price fields exist', () => {
      const form: FormInfo = {
        action: '/submit',
        method: 'POST',
        inputs: [{ name: 'name', type: 'text' }],
        pageUrl: 'https://example.com',
      };
      expect(getPriceFields(form)).toHaveLength(0);
    });
  });

  describe('getQuantityFields()', () => {
    it('extracts quantity field names', () => {
      const form: FormInfo = {
        action: '/submit',
        method: 'POST',
        inputs: [
          { name: 'quantity', type: 'number' },
          { name: 'qty', type: 'text' },
          { name: 'name', type: 'text' },
        ],
        pageUrl: 'https://example.com',
      };
      const fields = getQuantityFields(form);
      expect(fields).toContain('quantity');
      expect(fields).toContain('qty');
      expect(fields).not.toContain('name');
    });

    it('returns empty array when no quantity fields exist', () => {
      const form: FormInfo = {
        action: '/submit',
        method: 'POST',
        inputs: [{ name: 'email', type: 'email' }],
        pageUrl: 'https://example.com',
      };
      expect(getQuantityFields(form)).toHaveLength(0);
    });
  });

  describe('hasStepParam()', () => {
    it('detects step= parameter', () => {
      expect(hasStepParam('https://example.com/checkout?step=1')).toBe(true);
    });

    it('detects page= parameter', () => {
      expect(hasStepParam('https://example.com/wizard?page=2')).toBe(true);
    });

    it('detects stage= parameter', () => {
      expect(hasStepParam('https://example.com/form?stage=3')).toBe(true);
    });

    it('detects phase= parameter', () => {
      expect(hasStepParam('https://example.com/process?phase=1')).toBe(true);
    });

    it('is case-insensitive', () => {
      expect(hasStepParam('https://example.com/form?Step=2')).toBe(true);
      expect(hasStepParam('https://example.com/form?STAGE=1')).toBe(true);
    });

    it('returns false for URLs without step params', () => {
      expect(hasStepParam('https://example.com/about')).toBe(false);
      expect(hasStepParam('https://example.com/form?name=test')).toBe(false);
    });
  });

  describe('extractStepParam()', () => {
    it('extracts step parameter name and value', () => {
      const result = extractStepParam('https://example.com/checkout?step=2');
      expect(result).not.toBeNull();
      expect(result!.param).toBe('step');
      expect(result!.value).toBe('2');
    });

    it('extracts page parameter', () => {
      const result = extractStepParam('https://example.com/wizard?page=3');
      expect(result).not.toBeNull();
      expect(result!.param).toBe('page');
      expect(result!.value).toBe('3');
    });

    it('returns null for URLs without step params', () => {
      expect(extractStepParam('https://example.com/about')).toBeNull();
      expect(extractStepParam('https://example.com?name=test')).toBeNull();
    });

    it('returns null for invalid URLs', () => {
      expect(extractStepParam('not-a-valid-url')).toBeNull();
    });
  });

  describe('filterBusinessForms()', () => {
    it('includes forms with business URLs', () => {
      const forms: FormInfo[] = [
        {
          action: '/cart/update',
          method: 'POST',
          inputs: [{ name: 'name', type: 'text' }],
          pageUrl: 'https://example.com/cart',
        },
      ];
      expect(filterBusinessForms(forms)).toHaveLength(1);
    });

    it('includes forms with business field names', () => {
      const forms: FormInfo[] = [
        {
          action: '/api/submit',
          method: 'POST',
          inputs: [{ name: 'price', type: 'hidden' }],
          pageUrl: 'https://example.com/product',
        },
      ];
      expect(filterBusinessForms(forms)).toHaveLength(1);
    });

    it('includes forms on business page URLs', () => {
      const forms: FormInfo[] = [
        {
          action: '/api/process',
          method: 'POST',
          inputs: [{ name: 'token', type: 'hidden' }],
          pageUrl: 'https://example.com/checkout',
        },
      ];
      expect(filterBusinessForms(forms)).toHaveLength(1);
    });

    it('excludes non-business forms', () => {
      const forms: FormInfo[] = [
        {
          action: '/login',
          method: 'POST',
          inputs: [
            { name: 'username', type: 'text' },
            { name: 'password', type: 'password' },
          ],
          pageUrl: 'https://example.com/login',
        },
        {
          action: '/search',
          method: 'GET',
          inputs: [{ name: 'q', type: 'text' }],
          pageUrl: 'https://example.com/search',
        },
      ];
      expect(filterBusinessForms(forms)).toHaveLength(0);
    });

    it('handles mixed forms — only returns business ones', () => {
      const forms: FormInfo[] = [
        {
          action: '/login',
          method: 'POST',
          inputs: [{ name: 'username', type: 'text' }],
          pageUrl: 'https://example.com/login',
        },
        {
          action: '/checkout/process',
          method: 'POST',
          inputs: [
            { name: 'price', type: 'hidden' },
            { name: 'quantity', type: 'number' },
          ],
          pageUrl: 'https://example.com/checkout',
        },
      ];
      const result = filterBusinessForms(forms);
      expect(result).toHaveLength(1);
      expect(result[0].action).toBe('/checkout/process');
    });
  });

  describe('PRICE_PAYLOADS', () => {
    it('includes zero value', () => {
      expect(PRICE_PAYLOADS).toContain('0');
    });

    it('includes negative value', () => {
      expect(PRICE_PAYLOADS).toContain('-1');
    });

    it('includes tiny value', () => {
      expect(PRICE_PAYLOADS).toContain('0.01');
    });

    it('includes extremely large value', () => {
      expect(PRICE_PAYLOADS).toContain('999999');
    });

    it('has exactly 4 payloads', () => {
      expect(PRICE_PAYLOADS).toHaveLength(4);
    });
  });

  describe('QUANTITY_PAYLOADS', () => {
    it('includes zero value', () => {
      expect(QUANTITY_PAYLOADS).toContain('0');
    });

    it('includes negative value', () => {
      expect(QUANTITY_PAYLOADS).toContain('-1');
    });

    it('includes extremely large value', () => {
      expect(QUANTITY_PAYLOADS).toContain('999999');
    });

    it('has exactly 3 payloads', () => {
      expect(QUANTITY_PAYLOADS).toHaveLength(3);
    });
  });

  describe('STEP_PARAM_PATTERNS', () => {
    it('matches step= pattern', () => {
      expect(STEP_PARAM_PATTERNS.some((p) => p.test('step=1'))).toBe(true);
    });

    it('matches page= pattern', () => {
      expect(STEP_PARAM_PATTERNS.some((p) => p.test('page=2'))).toBe(true);
    });

    it('matches stage= pattern', () => {
      expect(STEP_PARAM_PATTERNS.some((p) => p.test('stage=3'))).toBe(true);
    });

    it('matches phase= pattern', () => {
      expect(STEP_PARAM_PATTERNS.some((p) => p.test('phase=1'))).toBe(true);
    });

    it('has exactly 4 patterns', () => {
      expect(STEP_PARAM_PATTERNS).toHaveLength(4);
    });
  });

  describe('BUSINESS_URL_PATTERNS', () => {
    it('has at least 7 URL patterns', () => {
      expect(BUSINESS_URL_PATTERNS.length).toBeGreaterThanOrEqual(7);
    });
  });

  describe('BUSINESS_FIELD_PATTERNS', () => {
    it('combines price, quantity, and coupon patterns', () => {
      const expectedLength =
        PRICE_FIELD_PATTERNS.length +
        QUANTITY_FIELD_PATTERNS.length +
        COUPON_FIELD_PATTERNS.length;
      expect(BUSINESS_FIELD_PATTERNS).toHaveLength(expectedLength);
    });
  });
});

describe('REST API commerce patterns', () => {
  it('matches /api/BasketItems style URLs', () => {
    expect(isBusinessUrl('http://localhost:3000/api/BasketItems')).toBe(true);
  });

  it('matches /rest/basket/ style URLs', () => {
    expect(isBusinessUrl('http://localhost:3000/rest/basket/1')).toBe(true);
  });

  it('matches /api/Products style URLs', () => {
    expect(isBusinessUrl('http://localhost:3000/api/Products/1')).toBe(true);
  });

  it('matches /api/Orders style URLs', () => {
    expect(isBusinessUrl('http://localhost:3000/api/Orders')).toBe(true);
  });

  it('matches /api/coupon style URLs', () => {
    expect(isBusinessUrl('http://localhost:3000/api/coupon/apply')).toBe(true);
  });

  it('does not match non-business API URLs', () => {
    expect(isBusinessUrl('http://localhost:3000/api/Challenges')).toBe(false);
    expect(isBusinessUrl('http://localhost:3000/api/Users')).toBe(false);
    expect(isBusinessUrl('http://localhost:3000/rest/languages')).toBe(false);
  });
});

describe('filterBusinessApiEndpoints', () => {
  it('filters pages and API endpoints to business-relevant ones', () => {
    const pages = [
      'http://localhost:3000/',
      'http://localhost:3000/rest/basket/1',
      'http://localhost:3000/api/Products',
    ];
    const apiEndpoints = [
      'http://localhost:3000/api/Challenges',
      'http://localhost:3000/api/BasketItems',
    ];
    const result = filterBusinessApiEndpoints(pages, apiEndpoints);
    expect(result).toContain('http://localhost:3000/rest/basket/1');
    expect(result).toContain('http://localhost:3000/api/Products');
    expect(result).toContain('http://localhost:3000/api/BasketItems');
    expect(result).not.toContain('http://localhost:3000/api/Challenges');
    expect(result).not.toContain('http://localhost:3000/');
  });

  it('deduplicates URLs appearing in both pages and apiEndpoints', () => {
    const pages = ['http://localhost:3000/api/Products'];
    const apiEndpoints = ['http://localhost:3000/api/Products'];
    const result = filterBusinessApiEndpoints(pages, apiEndpoints);
    expect(result).toHaveLength(1);
  });

  it('returns empty for non-business endpoints', () => {
    const pages = ['http://localhost:3000/'];
    const apiEndpoints = ['http://localhost:3000/api/Challenges'];
    const result = filterBusinessApiEndpoints(pages, apiEndpoints);
    expect(result).toHaveLength(0);
  });
});
