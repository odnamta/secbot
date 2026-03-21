import { describe, it, expect } from 'vitest';
import {
  DESERIALIZATION_PAYLOADS,
  DESERIALIZATION_ERROR_PATTERNS,
  DESERIALIZATION_URL_PATTERNS,
  SERIALIZATION_CONTENT_TYPES,
  detectDeserializationError,
} from '../../src/config/payloads/deserialize.js';

describe('Insecure Deserialization Payloads', () => {
  it('has at least 10 payloads covering multiple formats', () => {
    expect(DESERIALIZATION_PAYLOADS.length).toBeGreaterThanOrEqual(10);
  });

  it('covers all major serialization formats', () => {
    const formats = new Set(DESERIALIZATION_PAYLOADS.map((p) => p.format));
    expect(formats.has('java')).toBe(true);
    expect(formats.has('php')).toBe(true);
    expect(formats.has('python-pickle')).toBe(true);
    expect(formats.has('node-serialize')).toBe(true);
    expect(formats.has('ruby-marshal')).toBe(true);
    expect(formats.has('dotnet')).toBe(true);
    expect(formats.has('yaml')).toBe(true);
  });

  it('all payloads have required fields', () => {
    for (const p of DESERIALIZATION_PAYLOADS) {
      expect(p.payload).toBeTruthy();
      expect(p.contentType).toBeTruthy();
      expect(p.format).toBeTruthy();
      expect(p.indicator).toBeInstanceOf(RegExp);
      expect(p.technique).toBeTruthy();
      expect(p.cwe).toBe('CWE-502');
    }
  });

  it('all techniques are unique', () => {
    const techniques = DESERIALIZATION_PAYLOADS.map((p) => p.technique);
    expect(new Set(techniques).size).toBe(techniques.length);
  });

  it('Java payloads target ObjectInputStream', () => {
    const javaPayloads = DESERIALIZATION_PAYLOADS.filter((p) => p.format === 'java');
    expect(javaPayloads.length).toBeGreaterThanOrEqual(2);
    for (const p of javaPayloads) {
      expect(p.indicator.test('java.io.ObjectInputStream')).toBe(true);
    }
  });

  it('PHP payloads target unserialize()', () => {
    const phpPayloads = DESERIALIZATION_PAYLOADS.filter((p) => p.format === 'php');
    expect(phpPayloads.length).toBeGreaterThanOrEqual(2);
    // PHP serialized format: O:length:"classname":...
    const hasSerializedFormat = phpPayloads.some((p) => /O:\d+:/.test(p.payload));
    expect(hasSerializedFormat).toBe(true);
  });

  it('node-serialize payload contains IIFE pattern', () => {
    const nodePayload = DESERIALIZATION_PAYLOADS.find((p) => p.format === 'node-serialize');
    expect(nodePayload).toBeDefined();
    expect(nodePayload!.payload).toContain('_$$ND_FUNC$$_');
  });

  it('YAML payloads include Python and Java variants', () => {
    const yamlPayloads = DESERIALIZATION_PAYLOADS.filter((p) => p.format === 'yaml');
    expect(yamlPayloads.length).toBeGreaterThanOrEqual(2);
    const hasPython = yamlPayloads.some((p) => p.payload.includes('!!python'));
    const hasJava = yamlPayloads.some((p) => p.payload.includes('javax.script'));
    expect(hasPython).toBe(true);
    expect(hasJava).toBe(true);
  });

  it('generic JSON $type payload targets .NET type confusion', () => {
    const genericPayload = DESERIALIZATION_PAYLOADS.find((p) => p.format === 'generic');
    expect(genericPayload).toBeDefined();
    expect(genericPayload!.payload).toContain('$type');
  });
});

describe('detectDeserializationError()', () => {
  it('detects Java ObjectInputStream errors', () => {
    const result = detectDeserializationError(
      'Error: java.io.ObjectInputStream reading object failed',
    );
    expect(result.detected).toBe(true);
  });

  it('detects PHP unserialize errors', () => {
    const result = detectDeserializationError(
      'Warning: unserialize() Error at offset 15 of 20 bytes',
    );
    expect(result.detected).toBe(true);
  });

  it('detects Python pickle errors', () => {
    const result = detectDeserializationError(
      'pickle.loads failed: unpickling stack underflow',
    );
    expect(result.detected).toBe(true);
  });

  it('detects Node.js node-serialize references', () => {
    const result = detectDeserializationError(
      'Error in node-serialize module',
    );
    expect(result.detected).toBe(true);
  });

  it('detects Ruby Marshal errors', () => {
    const result = detectDeserializationError(
      'incompatible marshal file format (can\'t read)',
    );
    expect(result.detected).toBe(true);
  });

  it('detects .NET BinaryFormatter errors', () => {
    const result = detectDeserializationError(
      'System.Runtime.Serialization.SerializationException: BinaryFormatter disallowed',
    );
    expect(result.detected).toBe(true);
  });

  it('detects YAML unsafe_load errors', () => {
    const result = detectDeserializationError(
      'yaml.unsafe_load is deprecated, use yaml.full_load',
    );
    expect(result.detected).toBe(true);
  });

  it('does NOT flag normal JSON responses', () => {
    const result = detectDeserializationError('{"status":"ok","data":[1,2,3]}');
    expect(result.detected).toBe(false);
  });

  it('does NOT flag normal HTML responses', () => {
    const result = detectDeserializationError(
      '<html><body><h1>Welcome</h1></body></html>',
    );
    expect(result.detected).toBe(false);
  });

  it('does NOT flag generic 404 responses', () => {
    const result = detectDeserializationError(
      'Not Found: The requested URL was not found on this server.',
    );
    expect(result.detected).toBe(false);
  });
});

describe('DESERIALIZATION_ERROR_PATTERNS', () => {
  it('has patterns for all major platforms', () => {
    // Should have at least 20 patterns across all platforms
    expect(DESERIALIZATION_ERROR_PATTERNS.length).toBeGreaterThanOrEqual(20);
  });

  it('all patterns are RegExp instances', () => {
    for (const pattern of DESERIALIZATION_ERROR_PATTERNS) {
      expect(pattern).toBeInstanceOf(RegExp);
    }
  });
});

describe('DESERIALIZATION_URL_PATTERNS', () => {
  it('matches common API paths', () => {
    expect(DESERIALIZATION_URL_PATTERNS.some((p) => p.test('/api/data'))).toBe(true);
    expect(DESERIALIZATION_URL_PATTERNS.some((p) => p.test('/webhook/handle'))).toBe(true);
    expect(DESERIALIZATION_URL_PATTERNS.some((p) => p.test('/rpc/call'))).toBe(true);
  });

  it('matches .NET handler extensions', () => {
    expect(DESERIALIZATION_URL_PATTERNS.some((p) => p.test('/handler.ashx'))).toBe(true);
    expect(DESERIALIZATION_URL_PATTERNS.some((p) => p.test('/service.asmx'))).toBe(true);
  });

  it('does NOT match simple static paths', () => {
    const staticPaths = ['/index.html', '/style.css', '/image.png', '/about'];
    for (const path of staticPaths) {
      const matches = DESERIALIZATION_URL_PATTERNS.some((p) => p.test(path));
      expect(matches).toBe(false);
    }
  });
});

describe('SERIALIZATION_CONTENT_TYPES', () => {
  it('includes Java serialization content type', () => {
    expect(SERIALIZATION_CONTENT_TYPES).toContain('application/x-java-serialized-object');
  });

  it('includes YAML content types', () => {
    expect(SERIALIZATION_CONTENT_TYPES).toContain('application/x-yaml');
  });

  it('includes common content types', () => {
    expect(SERIALIZATION_CONTENT_TYPES).toContain('application/json');
    expect(SERIALIZATION_CONTENT_TYPES).toContain('application/octet-stream');
  });
});

describe('insecure-deserialization check module', () => {
  it('exports check with correct interface', async () => {
    const { insecureDeserializationCheck } = await import(
      '../../src/scanner/active/insecure-deserialization.js'
    );
    expect(insecureDeserializationCheck.name).toBe('insecure-deserialization');
    expect(insecureDeserializationCheck.category).toBe('insecure-deserialization');
    expect(insecureDeserializationCheck.parallel).toBe(false);
    expect(typeof insecureDeserializationCheck.run).toBe('function');
  });
});
