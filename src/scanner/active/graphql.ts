import { randomUUID } from 'node:crypto';
import type { BrowserContext } from 'playwright';
import type { RawFinding, ScanConfig } from '../types.js';
import { log } from '../../utils/logger.js';
import type { RequestLogger } from '../../utils/request-logger.js';
import type { ActiveCheck, ScanTargets } from './index.js';
import { delay } from '../../utils/shared.js';

/** Common GraphQL endpoint paths */
const GRAPHQL_PATHS = ['/graphql', '/api/graphql', '/graphql/v1', '/gql'];

/** Full introspection query to discover schema */
const INTROSPECTION_QUERY = `{
  __schema {
    queryType { name }
    mutationType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
  }
}`;

/** Deeply nested query to test depth limiting (10 levels) */
const DEPTH_QUERY = `{
  __schema {
    types {
      fields {
        type {
          ofType {
            ofType {
              ofType {
                ofType {
                  ofType {
                    name
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}`;

/** Batch query — sends multiple operations in one request */
const BATCH_QUERIES = [
  { query: '{ __typename }' },
  { query: '{ __typename }' },
  { query: '{ __typename }' },
  { query: '{ __typename }' },
  { query: '{ __typename }' },
];

/**
 * GraphQL security check.
 *
 * Tests GraphQL endpoints for:
 * 1. Introspection enabled (schema exposure)
 * 2. No query depth limiting (DoS via deeply nested queries)
 * 3. Batch query support without limits (DoS amplification)
 * 4. Mutation discovery (sensitive operations exposed)
 *
 * OWASP: A01:2021 – Broken Access Control, A05:2021 – Security Misconfiguration
 */
export const graphqlCheck: ActiveCheck = {
  name: 'graphql',
  category: 'info-disclosure',
  async run(context, targets, config, requestLogger) {
    const findings: RawFinding[] = [];

    // Find GraphQL endpoints from crawled data + common paths
    const graphqlEndpoints = findGraphqlEndpoints(targets, config.targetUrl);
    if (graphqlEndpoints.length === 0) {
      log.info('GraphQL check: no endpoints found');
      return findings;
    }

    log.info(`Testing ${graphqlEndpoints.length} GraphQL endpoint(s)...`);

    for (const endpoint of graphqlEndpoints) {
      // Test introspection
      const introResult = await testIntrospection(context, endpoint, config, requestLogger);
      if (introResult) {
        findings.push(introResult.finding);

        // If introspection succeeded, analyze the schema for sensitive mutations
        if (introResult.schema) {
          const mutationFindings = analyzeMutations(introResult.schema, endpoint);
          findings.push(...mutationFindings);
        }
      }

      await delay(config.requestDelay);

      // Test depth limiting
      const depthFinding = await testDepthLimit(context, endpoint, config, requestLogger);
      if (depthFinding) findings.push(depthFinding);

      await delay(config.requestDelay);

      // Test batch query support
      const batchFinding = await testBatchQueries(context, endpoint, config, requestLogger);
      if (batchFinding) findings.push(batchFinding);
    }

    log.info(`GraphQL check: ${findings.length} finding(s)`);
    return findings;
  },
};

/**
 * Find GraphQL endpoints from crawled pages and common paths.
 */
function findGraphqlEndpoints(targets: ScanTargets, targetUrl: string): string[] {
  const endpoints = new Set<string>();
  const origin = new URL(targetUrl).origin;

  // Check crawled pages/APIs for GraphQL paths
  for (const url of [...targets.pages, ...targets.apiEndpoints]) {
    if (/graphql|gql/i.test(url)) {
      endpoints.add(url.split('?')[0]); // Strip query params
    }
  }

  // Add common paths if not found
  if (endpoints.size === 0) {
    for (const path of GRAPHQL_PATHS) {
      endpoints.add(`${origin}${path}`);
    }
  }

  return [...endpoints].slice(0, 3);
}

interface IntrospectionResult {
  finding: RawFinding;
  schema: Record<string, unknown> | null;
}

/**
 * Test if GraphQL introspection is enabled.
 */
async function testIntrospection(
  context: BrowserContext,
  endpoint: string,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<IntrospectionResult | null> {
  const page = await context.newPage();
  try {
    const response = await page.request.fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      data: JSON.stringify({ query: INTROSPECTION_QUERY }),
      timeout: config.timeout,
    });

    const status = response.status();
    const body = await response.text();

    requestLogger?.log({
      timestamp: new Date().toISOString(),
      method: 'POST',
      url: endpoint,
      responseStatus: status,
      phase: 'active-graphql-introspection',
    });

    if (status >= 200 && status < 300) {
      try {
        const parsed = JSON.parse(body);
        if (parsed?.data?.__schema) {
          const schema = parsed.data.__schema;
          const types = schema.types || [];
          const queryType = schema.queryType?.name;
          const mutationType = schema.mutationType?.name;

          // Count user-defined types (exclude built-in __* types)
          const userTypes = types.filter((t: { name: string }) =>
            t.name && !t.name.startsWith('__'),
          );

          return {
            finding: {
              id: randomUUID(),
              category: 'info-disclosure',
              severity: 'medium',
              title: 'GraphQL Introspection Enabled — Full Schema Exposed',
              description: `The GraphQL endpoint at ${new URL(endpoint).pathname} has introspection enabled. The full API schema is accessible, revealing ${userTypes.length} types, query type "${queryType}", ${mutationType ? `mutation type "${mutationType}"` : 'no mutations'}. Attackers can use this to map the entire API surface and discover sensitive operations.`,
              url: endpoint,
              evidence: [
                `Types discovered: ${userTypes.length}`,
                `Query type: ${queryType || 'none'}`,
                `Mutation type: ${mutationType || 'none'}`,
                `User-defined types: ${userTypes.slice(0, 10).map((t: { name: string }) => t.name).join(', ')}${userTypes.length > 10 ? ` (+${userTypes.length - 10} more)` : ''}`,
              ].join('\n'),
              request: {
                method: 'POST',
                url: endpoint,
                body: JSON.stringify({ query: INTROSPECTION_QUERY }),
              },
              response: { status, bodySnippet: body.slice(0, 300) },
              timestamp: new Date().toISOString(),
            },
            schema,
          };
        }
      } catch {
        // Not valid JSON or no schema
      }
    }
  } catch (err) {
    log.debug(`GraphQL introspection test: ${(err as Error).message}`);
  } finally {
    await page.close();
  }

  return null;
}

/**
 * Analyze schema for sensitive mutations.
 */
function analyzeMutations(
  schema: Record<string, unknown>,
  endpoint: string,
): RawFinding[] {
  const findings: RawFinding[] = [];
  const types = (schema as { types?: Array<{ name: string; kind: string; fields?: Array<{ name: string }> }> }).types || [];
  const mutationTypeName = (schema as { mutationType?: { name: string } }).mutationType?.name;

  if (!mutationTypeName) return findings;

  const mutationType = types.find((t) => t.name === mutationTypeName);
  if (!mutationType?.fields) return findings;

  // Sensitive mutation patterns
  const sensitivePatterns = /^(delete|remove|drop|destroy|admin|create.*user|update.*role|grant|revoke|reset.*password|set.*admin|disable|enable|promote|transfer|withdraw|execute|run)/i;
  const sensitiveMutations = mutationType.fields.filter((f) =>
    sensitivePatterns.test(f.name),
  );

  if (sensitiveMutations.length > 0) {
    findings.push({
      id: randomUUID(),
      category: 'info-disclosure',
      severity: 'high',
      title: 'GraphQL Exposes Sensitive Mutations',
      description: `The GraphQL schema exposes ${sensitiveMutations.length} potentially dangerous mutations: ${sensitiveMutations.map((m) => m.name).join(', ')}. These operations may allow unauthorized data modification, user management, or privilege escalation if access controls are insufficient.`,
      url: endpoint,
      evidence: `Sensitive mutations found:\n${sensitiveMutations.map((m) => `  - ${m.name}`).join('\n')}`,
      timestamp: new Date().toISOString(),
    });
  }

  return findings;
}

/**
 * Test if the GraphQL endpoint enforces query depth limits.
 */
async function testDepthLimit(
  context: BrowserContext,
  endpoint: string,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding | null> {
  const page = await context.newPage();
  try {
    const response = await page.request.fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      data: JSON.stringify({ query: DEPTH_QUERY }),
      timeout: config.timeout,
    });

    const status = response.status();
    const body = await response.text();

    requestLogger?.log({
      timestamp: new Date().toISOString(),
      method: 'POST',
      url: endpoint,
      responseStatus: status,
      phase: 'active-graphql-depth',
    });

    if (status >= 200 && status < 300) {
      try {
        const parsed = JSON.parse(body);
        // If the deeply nested query succeeds without errors, no depth limiting
        if (parsed?.data && !parsed?.errors) {
          return {
            id: randomUUID(),
            category: 'info-disclosure',
            severity: 'medium',
            title: 'GraphQL Has No Query Depth Limit',
            description: `The GraphQL endpoint at ${new URL(endpoint).pathname} accepted a deeply nested query (10+ levels) without rejection. An attacker can craft recursive queries that consume excessive server resources, leading to denial of service.`,
            url: endpoint,
            evidence: `Sent a 10-level nested query — server responded with HTTP ${status} and valid data (no depth limit errors).`,
            request: { method: 'POST', url: endpoint },
            response: { status, bodySnippet: body.slice(0, 200) },
            timestamp: new Date().toISOString(),
          };
        }
      } catch {
        // Not valid JSON
      }
    }
  } catch (err) {
    log.debug(`GraphQL depth test: ${(err as Error).message}`);
  } finally {
    await page.close();
  }

  return null;
}

/**
 * Test if the GraphQL endpoint supports batch queries without limits.
 */
async function testBatchQueries(
  context: BrowserContext,
  endpoint: string,
  config: ScanConfig,
  requestLogger?: RequestLogger,
): Promise<RawFinding | null> {
  const page = await context.newPage();
  try {
    const response = await page.request.fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      data: JSON.stringify(BATCH_QUERIES),
      timeout: config.timeout,
    });

    const status = response.status();
    const body = await response.text();

    requestLogger?.log({
      timestamp: new Date().toISOString(),
      method: 'POST',
      url: endpoint,
      responseStatus: status,
      phase: 'active-graphql-batch',
    });

    if (status >= 200 && status < 300) {
      try {
        const parsed = JSON.parse(body);
        // If the response is an array with results for each query, batch is supported
        if (Array.isArray(parsed) && parsed.length >= BATCH_QUERIES.length) {
          return {
            id: randomUUID(),
            category: 'info-disclosure',
            severity: 'low',
            title: 'GraphQL Batch Queries Supported Without Limits',
            description: `The GraphQL endpoint at ${new URL(endpoint).pathname} accepts batch queries (multiple operations in one request). Without rate limiting per operation, an attacker can amplify queries — sending ${BATCH_QUERIES.length} queries as one request to bypass per-request rate limits.`,
            url: endpoint,
            evidence: `Sent ${BATCH_QUERIES.length} queries as a batch — server responded with ${parsed.length} results. No batch limit enforced.`,
            request: { method: 'POST', url: endpoint },
            response: { status, bodySnippet: body.slice(0, 200) },
            timestamp: new Date().toISOString(),
          };
        }
      } catch {
        // Not valid JSON
      }
    }
  } catch (err) {
    log.debug(`GraphQL batch test: ${(err as Error).message}`);
  } finally {
    await page.close();
  }

  return null;
}
