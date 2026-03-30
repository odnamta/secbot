import { FastEngine } from '../fast-engine.js';
import { log } from '../../utils/logger.js';
import { scanJsForSecrets } from '../active/info-disclosure.js';

// ─── Types ────────────────────────────────────────────────────────

export interface JSAnalysisResult {
  /** API endpoints extracted from JS (full URLs or paths) */
  apiEndpoints: string[];
  /** GraphQL queries/mutations found */
  graphqlOperations: string[];
  /** Parameter names used in fetch/XHR calls */
  paramNames: string[];
  /** Webpack/Vite chunk URLs for further analysis */
  chunkUrls: string[];
  /** Secrets/tokens found in JS source */
  secrets: Array<{ type: string; value: string; file: string }>;
  /** Total JS files analyzed */
  filesAnalyzed: number;
}

export interface JSAnalysisOptions {
  /** Maximum JS files to download and analyze (default: 50) */
  maxFiles?: number;
  /** Maximum file size in bytes (default: 2MB) */
  maxFileSize?: number;
  /** Concurrency for HTTP fetches (default: 10) */
  concurrency?: number;
  /** Per-request timeout in ms (default: 10000) */
  timeout?: number;
  /** HTTP proxy URL */
  proxy?: string;
  /** Custom user agent */
  userAgent?: string;
  /** Extra headers (e.g. auth) */
  extraHeaders?: Record<string, string>;
}

// ─── Extraction: API Endpoints ────────────────────────────────────

/** Paths that are clearly not API endpoints */
const NOISE_PATH_RE = /\.(css|png|jpe?g|gif|svg|woff2?|ttf|eot|ico|map)(\?|$)/i;
const NODE_MODULES_RE = /node_modules/;

/**
 * Extract API endpoints from JS source code.
 * Covers fetch(), axios, XHR, string literals with /api/ or /v\d+/ prefixes,
 * and template literal bases (without interpolation).
 */
export function extractEndpoints(jsContent: string): string[] {
  const endpoints: Set<string> = new Set();

  // fetch() calls: fetch('/api/users', ...) or fetch("/api/users")
  const fetchRe = /fetch\s*\(\s*['"`]([^'"`\s${}]+)['"`]/g;
  // axios calls: axios.get('/api/users'), axios.post('/api/data'), axios('/api/x')
  const axiosMethodRe = /axios\.\w+\s*\(\s*['"`]([^'"`\s${}]+)['"`]/g;
  const axiosDirectRe = /axios\s*\(\s*['"`]([^'"`\s${}]+)['"`]/g;
  // axios config: { url: '/api/endpoint' }
  const axiosUrlRe = /url\s*:\s*['"`](\/[^'"`\s${}]+)['"`]/g;
  // XHR: xhr.open('GET', '/api/endpoint')
  const xhrRe = /\.open\s*\(\s*['"`]\w+['"`]\s*,\s*['"`]([^'"`\s]+)['"`]/g;
  // String literals that look like API paths: '/api/...'
  const apiPathRe = /['"`](\/api\/[a-zA-Z0-9/_.-]+)['"`]/g;
  // REST versioned endpoints: '/v1/users', '/v2/products'
  const restRe = /['"`](\/v[0-9]+\/[a-zA-Z0-9/_.-]+)['"`]/g;
  // Absolute URL API endpoints: 'https://api.example.com/...'
  const absoluteApiRe = /['"`](https?:\/\/[a-zA-Z0-9._-]+\/[a-zA-Z0-9/_.-]+)['"`]/g;
  // Route definitions: router.get('/path'), app.post('/path')
  const routerRe = /(?:router|app|server)\.\s*(?:get|post|put|patch|delete|options|head|all)\s*\(\s*['"`]([^'"`\s]+)['"`]/g;

  const regexes = [
    fetchRe, axiosMethodRe, axiosDirectRe, axiosUrlRe,
    xhrRe, apiPathRe, restRe, absoluteApiRe, routerRe,
  ];

  for (const re of regexes) {
    let match;
    while ((match = re.exec(jsContent)) !== null) {
      const path = match[1];
      // Validate: reasonable length, not noise
      if (
        path.length > 3 &&
        path.length < 300 &&
        !NODE_MODULES_RE.test(path) &&
        !NOISE_PATH_RE.test(path)
      ) {
        endpoints.add(path);
      }
    }
  }

  return [...endpoints];
}

// ─── Extraction: GraphQL Operations ───────────────────────────────

/**
 * Extract GraphQL operation names from JS source.
 * Matches:
 * - Named queries/mutations/subscriptions: query GetUsers { ... }
 * - gql`` tagged template literals containing operation names
 * - operationName fields in request configs
 */
export function extractGraphQL(jsContent: string): string[] {
  const ops: Set<string> = new Set();

  // query/mutation/subscription names: query GetUsers, mutation CreateUser
  const gqlNameRe = /(?:query|mutation|subscription)\s+([A-Z][a-zA-Z0-9_]+)/g;
  // operationName in JSON: "operationName":"GetUsers" or operationName: "GetUsers"
  const opNameRe = /operationName['":\s]+['"]([A-Z][a-zA-Z0-9_]+)['"]/g;
  // GraphQL field selection patterns (common operation names in variables)
  const gqlDocRe = /gql\s*`[^`]*(?:query|mutation|subscription)\s+([A-Z][a-zA-Z0-9_]+)/g;

  for (const re of [gqlNameRe, opNameRe, gqlDocRe]) {
    let match;
    while ((match = re.exec(jsContent)) !== null) {
      ops.add(match[1]);
    }
  }

  return [...ops];
}

// ─── Extraction: Parameter Names ──────────────────────────────────

/** Common JS keywords/builtins that should not be treated as param names */
const JS_KEYWORDS = new Set([
  'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'break', 'continue',
  'return', 'function', 'class', 'new', 'delete', 'typeof', 'instanceof',
  'var', 'let', 'const', 'this', 'true', 'false', 'null', 'undefined',
  'try', 'catch', 'finally', 'throw', 'import', 'export', 'default',
  'async', 'await', 'yield', 'void', 'in', 'of', 'with', 'debugger',
  'prototype', 'constructor', 'toString', 'valueOf', 'hasOwnProperty',
  'length', 'push', 'pop', 'shift', 'map', 'filter', 'reduce', 'forEach',
  'then', 'catch', 'finally', 'resolve', 'reject', 'Promise',
  'Object', 'Array', 'String', 'Number', 'Boolean', 'Date', 'Math',
  'JSON', 'Error', 'RegExp', 'Map', 'Set', 'Symbol', 'Proxy',
  'console', 'window', 'document', 'navigator', 'location',
  'type', 'interface', 'enum', 'extends', 'implements',
  'React', 'useState', 'useEffect', 'useRef', 'useMemo', 'useCallback',
  'Component', 'props', 'state', 'render', 'children',
  'key', 'value', 'index', 'item', 'event', 'error', 'data', 'result',
  'module', 'exports', 'require', 'process', 'global', 'Buffer',
  'width', 'height', 'style', 'className', 'onClick', 'onChange',
  'src', 'href', 'alt', 'title', 'name', 'id', 'disabled', 'hidden',
]);

/**
 * Extract parameter names from JS fetch/XHR calls and request body objects.
 * Focuses on params that appear in network request contexts.
 */
export function extractParamNames(jsContent: string): string[] {
  const params: Set<string> = new Set();

  // URL query params: ?key=value or &key=value
  const urlParamRe = /[?&]([a-zA-Z_][a-zA-Z0-9_]*)=/g;
  // FormData: formData.append('field', ...)
  const formDataRe = /\.append\s*\(\s*['"`]([a-zA-Z_][a-zA-Z0-9_]*)['"`]/g;
  // URLSearchParams: searchParams.set('key', ...) / searchParams.append('key', ...)
  const searchParamsRe = /searchParams\.(?:set|append|get|has|delete)\s*\(\s*['"`]([a-zA-Z_][a-zA-Z0-9_]*)['"`]/g;
  // JSON.stringify body keys near fetch/axios calls (within 500 chars of fetch)
  const bodyKeyRe = /(?:body|data|params|payload|json)\s*:\s*\{([^}]{1,500})\}/g;
  // Direct object literal keys near request methods
  const requestBodyRe = /(?:fetch|axios|post|put|patch|request)\s*\([^)]*\{([^}]{1,300})\}/g;

  // Simple param extraction from URL patterns
  for (const re of [urlParamRe, formDataRe, searchParamsRe]) {
    let match;
    while ((match = re.exec(jsContent)) !== null) {
      const param = match[1];
      if (param.length > 1 && param.length < 50 && !JS_KEYWORDS.has(param)) {
        params.add(param);
      }
    }
  }

  // Extract keys from body/data objects (requires parsing object literal content)
  for (const re of [bodyKeyRe, requestBodyRe]) {
    let match;
    while ((match = re.exec(jsContent)) !== null) {
      const objectContent = match[1];
      const keyRe = /['"`]?([a-zA-Z_][a-zA-Z0-9_]*)['"`]?\s*:/g;
      let keyMatch;
      while ((keyMatch = keyRe.exec(objectContent)) !== null) {
        const param = keyMatch[1];
        if (param.length > 1 && param.length < 50 && !JS_KEYWORDS.has(param)) {
          params.add(param);
        }
      }
    }
  }

  return [...params];
}

// ─── Extraction: Chunk URLs ───────────────────────────────────────

/**
 * Extract webpack/Vite/Rollup chunk URLs from JS source.
 * Returns fully resolved absolute URLs.
 */
export function extractChunkUrls(jsContent: string, baseUrl: string): string[] {
  const chunks: Set<string> = new Set();

  // Webpack chunks: "static/js/chunk-abc123.js" or "chunk.abc.js"
  const wpChunkRe = /["']([a-zA-Z0-9/_.-]+\.chunk\.js)["']/g;
  // Webpack hash chunks: __webpack_require__.p + "static/js/123.abc.js"
  const wpHashRe = /["']([a-zA-Z0-9/_.-]+\.[a-f0-9]{6,}\.js)["']/g;
  // Vite dynamic imports: import("/assets/module-abc123.js")
  const viteRe = /import\s*\(\s*["']([^"']+\.js)["']\s*\)/g;
  // Generic JS file references that look like chunks (contain hash)
  const jsHashRefRe = /["'](\/[a-zA-Z0-9/_.-]*[a-f0-9]{8}[a-zA-Z0-9/_.-]*\.js)["']/g;
  // Next.js chunks: /_next/static/chunks/...
  const nextChunkRe = /["'](\/_next\/static\/chunks\/[^"']+\.js)["']/g;

  for (const re of [wpChunkRe, wpHashRe, viteRe, jsHashRefRe, nextChunkRe]) {
    let match;
    while ((match = re.exec(jsContent)) !== null) {
      const path = match[1];
      try {
        if (path.startsWith('http://') || path.startsWith('https://')) {
          chunks.add(path);
        } else {
          chunks.add(new URL(path, baseUrl).href);
        }
      } catch {
        // Skip malformed URLs
      }
    }
  }

  // Don't re-discover the same URL we started with
  chunks.delete(baseUrl);

  return [...chunks];
}

// ─── Secret Detection (reuses info-disclosure patterns) ───────────

interface SecretResult {
  type: string;
  value: string;
  file: string;
}

/**
 * Scan JS content for hardcoded secrets, delegating to the shared
 * scanJsForSecrets from info-disclosure.ts.
 */
function extractSecrets(jsContent: string, sourceUrl: string): SecretResult[] {
  const found = scanJsForSecrets(jsContent, sourceUrl);
  return found.map((s) => ({
    type: s.name,
    value: s.match,
    file: sourceUrl,
  }));
}

// ─── URL Collection ───────────────────────────────────────────────

/** Tracking/analytics script URL patterns that should be skipped. */
const TRACKING_SCRIPT_RE = /(?:google-analytics|googletagmanager|facebook\.net\/|connect\.facebook|analytics|pixel|beacon|hotjar|segment\.com|mixpanel|amplitude|sentry|datadome|cloudflareinsights|newrelic|nr-data|doubleclick|googlesyndication|googleadservices)/i;

/** JS file extensions worth analyzing */
const JS_EXT_RE = /\.(?:js|mjs|cjs)(?:\?|$)/i;

/**
 * Collect unique JS URLs from crawled pages. Filters out:
 * - Tracking/analytics scripts
 * - Non-JS URLs
 * - Duplicate URLs
 *
 * Prioritizes same-origin scripts (more likely to contain app logic).
 */
export function collectJsUrls(
  scripts: string[],
  targetOrigin: string,
): string[] {
  const seen = new Set<string>();
  const result: string[] = [];

  for (const url of scripts) {
    // Skip empty, data URIs, blobs
    if (!url || url.startsWith('data:') || url.startsWith('blob:')) continue;

    // Must look like a JS file
    try {
      const parsed = new URL(url);
      if (!JS_EXT_RE.test(parsed.pathname) && !parsed.pathname.endsWith('.js')) continue;
    } catch {
      continue;
    }

    // Skip tracking/analytics
    if (TRACKING_SCRIPT_RE.test(url)) continue;

    // Deduplicate
    if (seen.has(url)) continue;
    seen.add(url);

    result.push(url);
  }

  // Prioritize same-origin scripts first (more likely to contain app logic)
  result.sort((a, b) => {
    const aLocal = a.startsWith(targetOrigin) ? 0 : 1;
    const bLocal = b.startsWith(targetOrigin) ? 0 : 1;
    return aLocal - bLocal;
  });

  return result;
}

// ─── Main Analysis Function ───────────────────────────────────────

/**
 * Deep JS bundle analysis — extracts the full attack surface from JavaScript files.
 *
 * 1. Collects all JS URLs from crawled pages (scripts arrays) + any chunk URLs
 * 2. Downloads each JS file via FastEngine (respecting limits)
 * 3. Runs all extractors on each file (endpoints, GraphQL, params, chunks, secrets)
 * 4. Follows discovered chunk URLs for one additional level of depth
 * 5. Aggregates and deduplicates results
 */
export async function analyzeJavaScript(
  scriptUrls: string[],
  targetUrl: string,
  options: JSAnalysisOptions = {},
): Promise<JSAnalysisResult> {
  const {
    maxFiles = 50,
    maxFileSize = 2 * 1024 * 1024, // 2MB
    concurrency = 10,
    timeout = 10000,
    proxy,
    userAgent,
    extraHeaders,
  } = options;

  const targetOrigin = new URL(targetUrl).origin;

  // Step 1: Collect and prioritize JS URLs
  const jsUrls = collectJsUrls(scriptUrls, targetOrigin);
  if (jsUrls.length === 0) {
    log.debug('JS analysis: no JS files to analyze');
    return emptyResult();
  }

  log.info(`JS analysis: ${jsUrls.length} JS files found, analyzing up to ${maxFiles}`);

  const engine = new FastEngine({
    concurrency,
    requestDelay: 0, // JS files are static assets, no rate limiting needed
    proxy,
    userAgent: userAgent ?? 'Mozilla/5.0 (compatible; SecBot/2.0)',
    defaultHeaders: extraHeaders,
  });

  // Accumulators
  const allEndpoints = new Set<string>();
  const allGraphqlOps = new Set<string>();
  const allParamNames = new Set<string>();
  const allChunkUrls = new Set<string>();
  const allSecrets: SecretResult[] = [];
  const seenSecretKeys = new Set<string>();
  let filesAnalyzed = 0;

  // Step 2: Download and analyze initial batch of JS files
  const initialUrls = jsUrls.slice(0, maxFiles);
  const responses = await engine.batch(initialUrls, { timeout });

  const analyzedUrls = new Set<string>();

  for (let i = 0; i < initialUrls.length; i++) {
    const resp = responses[i];
    if (!resp || resp.status < 200 || resp.status >= 300) continue;

    // Enforce max file size
    if (resp.body.length > maxFileSize) {
      log.debug(`JS analysis: skipping ${initialUrls[i]} (${(resp.body.length / 1024 / 1024).toFixed(1)}MB exceeds limit)`);
      continue;
    }

    analyzedUrls.add(initialUrls[i]);
    filesAnalyzed++;
    const content = resp.body;
    const fileUrl = initialUrls[i];

    // Run extractors
    for (const ep of extractEndpoints(content)) allEndpoints.add(ep);
    for (const op of extractGraphQL(content)) allGraphqlOps.add(op);
    for (const pn of extractParamNames(content)) allParamNames.add(pn);
    for (const cu of extractChunkUrls(content, fileUrl)) allChunkUrls.add(cu);

    // Secrets (deduplicate by type+value)
    for (const secret of extractSecrets(content, fileUrl)) {
      const key = `${secret.type}:${secret.value}`;
      if (!seenSecretKeys.has(key)) {
        seenSecretKeys.add(key);
        allSecrets.push(secret);
      }
    }
  }

  // Step 3: Follow discovered chunk URLs for one additional depth level
  // Only fetch chunks we haven't already analyzed, up to the max file limit
  const newChunkUrls = [...allChunkUrls].filter(
    (u) => !analyzedUrls.has(u),
  );

  const remainingBudget = maxFiles - filesAnalyzed;
  if (newChunkUrls.length > 0 && remainingBudget > 0) {
    const chunkBatch = newChunkUrls.slice(0, remainingBudget);
    log.debug(`JS analysis: following ${chunkBatch.length} discovered chunk URLs`);

    const chunkResponses = await engine.batch(chunkBatch, { timeout });

    for (let i = 0; i < chunkBatch.length; i++) {
      const resp = chunkResponses[i];
      if (!resp || resp.status < 200 || resp.status >= 300) continue;
      if (resp.body.length > maxFileSize) continue;

      analyzedUrls.add(chunkBatch[i]);
      filesAnalyzed++;
      const content = resp.body;
      const fileUrl = chunkBatch[i];

      for (const ep of extractEndpoints(content)) allEndpoints.add(ep);
      for (const op of extractGraphQL(content)) allGraphqlOps.add(op);
      for (const pn of extractParamNames(content)) allParamNames.add(pn);
      // Don't recurse into chunk-of-chunk URLs (one level is enough)

      for (const secret of extractSecrets(content, fileUrl)) {
        const key = `${secret.type}:${secret.value}`;
        if (!seenSecretKeys.has(key)) {
          seenSecretKeys.add(key);
          allSecrets.push(secret);
        }
      }
    }
  }

  const stats = engine.getStats();
  log.info(
    `JS analysis: analyzed ${filesAnalyzed} files, ` +
    `found ${allEndpoints.size} endpoints, ` +
    `${allGraphqlOps.size} GraphQL ops, ` +
    `${allParamNames.size} params, ` +
    `${allChunkUrls.size} chunk URLs, ` +
    `${allSecrets.length} secrets ` +
    `(${stats.total} requests, ${stats.errors} errors)`,
  );

  return {
    apiEndpoints: [...allEndpoints],
    graphqlOperations: [...allGraphqlOps],
    paramNames: [...allParamNames],
    chunkUrls: [...allChunkUrls],
    secrets: allSecrets,
    filesAnalyzed,
  };
}

// ─── Helpers ──────────────────────────────────────────────────────

function emptyResult(): JSAnalysisResult {
  return {
    apiEndpoints: [],
    graphqlOperations: [],
    paramNames: [],
    chunkUrls: [],
    secrets: [],
    filesAnalyzed: 0,
  };
}
