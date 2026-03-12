import { describe, it, expect, vi } from 'vitest';
import {
  fileUploadCheck,
  filterFileUploadForms,
  isUploadAccepted,
  buildMultipartData,
  UPLOAD_PAYLOADS,
} from '../../src/scanner/active/file-upload.js';
import type { FormInfo } from '../../src/scanner/types.js';

// Mock logger to suppress output during tests
vi.mock('../../src/utils/logger.js', () => ({
  log: {
    debug: vi.fn(),
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
  },
}));

// ---------------------------------------------------------------------------
// Metadata
// ---------------------------------------------------------------------------
describe('File Upload Check — Metadata', () => {
  it('has correct name', () => {
    expect(fileUploadCheck.name).toBe('file-upload');
  });

  it('has correct category', () => {
    expect(fileUploadCheck.category).toBe('file-upload');
  });

  it('does not have parallel flag', () => {
    expect(fileUploadCheck.parallel).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// filterFileUploadForms
// ---------------------------------------------------------------------------
describe('filterFileUploadForms()', () => {
  it('returns forms that have an input with type=file', () => {
    const forms: FormInfo[] = [
      {
        action: '/upload',
        method: 'POST',
        inputs: [
          { name: 'document', type: 'file' },
          { name: 'description', type: 'text' },
        ],
        pageUrl: 'https://example.com/form',
      },
    ];
    const result = filterFileUploadForms(forms);
    expect(result).toHaveLength(1);
    expect(result[0].action).toBe('/upload');
  });

  it('filters out forms without file inputs', () => {
    const forms: FormInfo[] = [
      {
        action: '/search',
        method: 'GET',
        inputs: [
          { name: 'q', type: 'text' },
        ],
        pageUrl: 'https://example.com/search',
      },
      {
        action: '/login',
        method: 'POST',
        inputs: [
          { name: 'user', type: 'text' },
          { name: 'pass', type: 'password' },
        ],
        pageUrl: 'https://example.com/login',
      },
    ];
    const result = filterFileUploadForms(forms);
    expect(result).toHaveLength(0);
  });

  it('returns multiple file upload forms', () => {
    const forms: FormInfo[] = [
      {
        action: '/upload-avatar',
        method: 'POST',
        inputs: [{ name: 'avatar', type: 'file' }],
        pageUrl: 'https://example.com/profile',
      },
      {
        action: '/upload-doc',
        method: 'POST',
        inputs: [{ name: 'doc', type: 'file' }],
        pageUrl: 'https://example.com/documents',
      },
      {
        action: '/search',
        method: 'GET',
        inputs: [{ name: 'q', type: 'text' }],
        pageUrl: 'https://example.com/search',
      },
    ];
    const result = filterFileUploadForms(forms);
    expect(result).toHaveLength(2);
  });

  it('returns empty array for empty input', () => {
    expect(filterFileUploadForms([])).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// isUploadAccepted
// ---------------------------------------------------------------------------
describe('isUploadAccepted()', () => {
  it('accepts 200 with normal body', () => {
    expect(isUploadAccepted(200, '{"success":true}')).toBe(true);
  });

  it('accepts 201 Created', () => {
    expect(isUploadAccepted(201, 'Created')).toBe(true);
  });

  it('rejects 400 Bad Request', () => {
    expect(isUploadAccepted(400, 'Bad request')).toBe(false);
  });

  it('rejects 403 Forbidden', () => {
    expect(isUploadAccepted(403, 'Forbidden')).toBe(false);
  });

  it('rejects 500 Internal Server Error', () => {
    expect(isUploadAccepted(500, 'Server error')).toBe(false);
  });

  it('rejects 200 with "file type not allowed" in body', () => {
    expect(isUploadAccepted(200, 'Error: file type not allowed')).toBe(false);
  });

  it('rejects 200 with "invalid file" in body', () => {
    expect(isUploadAccepted(200, 'The uploaded file is an invalid file.')).toBe(false);
  });

  it('rejects 200 with "upload failed" in body', () => {
    expect(isUploadAccepted(200, 'Upload failed: unsupported format')).toBe(false);
  });

  it('rejects 200 with "extension not allowed" in body', () => {
    expect(isUploadAccepted(200, 'Extension not allowed for this field.')).toBe(false);
  });

  it('is case-insensitive for error signals', () => {
    expect(isUploadAccepted(200, 'FILE TYPE NOT ALLOWED')).toBe(false);
    expect(isUploadAccepted(200, 'Rejected by server')).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Payload definitions
// ---------------------------------------------------------------------------
describe('UPLOAD_PAYLOADS', () => {
  it('has 4 payloads', () => {
    expect(UPLOAD_PAYLOADS).toHaveLength(4);
  });

  it('includes a shell extension payload', () => {
    const shell = UPLOAD_PAYLOADS.find((p) => p.label === 'shell-extension');
    expect(shell).toBeDefined();
    expect(shell!.filename).toBe('secbot-test.php');
    expect(shell!.body).toContain('secbot-upload-marker');
    expect(shell!.severity).toBe('critical');
  });

  it('includes a double extension payload', () => {
    const dbl = UPLOAD_PAYLOADS.find((p) => p.label === 'double-extension');
    expect(dbl).toBeDefined();
    expect(dbl!.filename).toBe('secbot-test.php.jpg');
    expect(dbl!.contentType).toBe('image/jpeg');
    expect(dbl!.severity).toBe('critical');
  });

  it('includes an SVG XSS payload', () => {
    const svg = UPLOAD_PAYLOADS.find((p) => p.label === 'svg-xss');
    expect(svg).toBeDefined();
    expect(svg!.filename).toMatch(/\.svg$/);
    expect(svg!.body).toContain('onload');
    expect(svg!.body).toContain('alert');
    expect(svg!.severity).toBe('high');
  });

  it('includes a MIME type bypass payload', () => {
    const mime = UPLOAD_PAYLOADS.find((p) => p.label === 'mime-type-bypass');
    expect(mime).toBeDefined();
    expect(mime!.filename).toMatch(/\.php$/);
    expect(mime!.contentType).toBe('image/jpeg');
    expect(mime!.severity).toBe('medium');
  });

  it('all payloads have required fields', () => {
    for (const p of UPLOAD_PAYLOADS) {
      expect(p.label).toBeTruthy();
      expect(p.filename).toBeTruthy();
      expect(p.contentType).toBeTruthy();
      expect(p.body).toBeTruthy();
      expect(p.risk).toBeTruthy();
      expect(['critical', 'high', 'medium']).toContain(p.severity);
    }
  });
});

// ---------------------------------------------------------------------------
// buildMultipartData
// ---------------------------------------------------------------------------
describe('buildMultipartData()', () => {
  const form: FormInfo = {
    action: '/upload',
    method: 'POST',
    inputs: [
      { name: 'avatar', type: 'file' },
      { name: 'description', type: 'text', value: 'my photo' },
      { name: 'csrf', type: 'hidden', value: 'tok123' },
    ],
    pageUrl: 'https://example.com/profile',
  };

  const payload = UPLOAD_PAYLOADS[0]; // shell-extension

  it('includes non-file inputs with their values', () => {
    const data = buildMultipartData(form, 'avatar', payload);
    expect(data['description']).toBe('my photo');
    expect(data['csrf']).toBe('tok123');
  });

  it('does not include file inputs as plain text', () => {
    const data = buildMultipartData(form, 'avatar', payload);
    // The file input should be the multipart object, not a string
    expect(typeof data['avatar']).toBe('object');
  });

  it('sets the file object with correct filename', () => {
    const data = buildMultipartData(form, 'avatar', payload);
    const file = data['avatar'] as { name: string; mimeType: string; buffer: Buffer };
    expect(file.name).toBe(payload.filename);
  });

  it('sets the file object with correct mimeType', () => {
    const data = buildMultipartData(form, 'avatar', payload);
    const file = data['avatar'] as { name: string; mimeType: string; buffer: Buffer };
    expect(file.mimeType).toBe(payload.contentType);
  });

  it('creates file content as Buffer (not writing to disk)', () => {
    const data = buildMultipartData(form, 'avatar', payload);
    const file = data['avatar'] as { name: string; mimeType: string; buffer: Buffer };
    expect(Buffer.isBuffer(file.buffer)).toBe(true);
    expect(file.buffer.toString('utf-8')).toBe(payload.body);
  });

  it('uses "test" as default for inputs without a value', () => {
    const formNoValues: FormInfo = {
      action: '/upload',
      method: 'POST',
      inputs: [
        { name: 'avatar', type: 'file' },
        { name: 'note', type: 'text' },
      ],
      pageUrl: 'https://example.com/upload',
    };
    const data = buildMultipartData(formNoValues, 'avatar', payload);
    expect(data['note']).toBe('test');
  });
});
