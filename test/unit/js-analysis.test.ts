import { describe, it, expect } from 'vitest';
import {
  extractEndpoints,
  extractGraphQL,
  extractParamNames,
  extractChunkUrls,
  collectJsUrls,
} from '../../src/scanner/discovery/js-analysis.js';

// ── extractEndpoints ──────────────────────────────────────────────

describe('extractEndpoints', () => {
  it('extracts fetch() URLs', () => {
    const js = `
      const resp = await fetch('/api/users', { method: 'GET' });
      fetch("/api/v2/orders");
    `;
    const eps = extractEndpoints(js);
    expect(eps).toContain('/api/users');
    expect(eps).toContain('/api/v2/orders');
  });

  it('extracts axios.method() URLs', () => {
    const js = `
      axios.get('/api/products');
      axios.post('/api/checkout', data);
      axios.delete("/api/users/123");
    `;
    const eps = extractEndpoints(js);
    expect(eps).toContain('/api/products');
    expect(eps).toContain('/api/checkout');
    expect(eps).toContain('/api/users/123');
  });

  it('extracts axios() direct calls', () => {
    const js = `axios('/api/config')`;
    const eps = extractEndpoints(js);
    expect(eps).toContain('/api/config');
  });

  it('extracts axios config URL property', () => {
    const js = `const config = { url: '/api/settings', method: 'GET' };`;
    const eps = extractEndpoints(js);
    expect(eps).toContain('/api/settings');
  });

  it('extracts XHR open() URLs', () => {
    const js = `
      xhr.open('GET', '/api/data');
      req.open("POST", "/v1/submit");
    `;
    const eps = extractEndpoints(js);
    expect(eps).toContain('/api/data');
    expect(eps).toContain('/v1/submit');
  });

  it('extracts API path string literals', () => {
    const js = `
      const endpoint = '/api/auth/login';
      const base = '/api/v2/payments';
    `;
    const eps = extractEndpoints(js);
    expect(eps).toContain('/api/auth/login');
    expect(eps).toContain('/api/v2/payments');
  });

  it('extracts versioned REST endpoints', () => {
    const js = `
      const url = '/v1/users';
      const other = '/v2/products/search';
      const v3 = '/v3/billing/invoices';
    `;
    const eps = extractEndpoints(js);
    expect(eps).toContain('/v1/users');
    expect(eps).toContain('/v2/products/search');
    expect(eps).toContain('/v3/billing/invoices');
  });

  it('extracts absolute API URLs', () => {
    const js = `fetch('https://api.example.com/v2/users')`;
    const eps = extractEndpoints(js);
    expect(eps).toContain('https://api.example.com/v2/users');
  });

  it('extracts router/app route definitions', () => {
    const js = `
      router.get('/users/:id', handler);
      app.post('/auth/login', loginHandler);
      server.delete('/api/session', logout);
    `;
    const eps = extractEndpoints(js);
    expect(eps).toContain('/users/:id');
    expect(eps).toContain('/auth/login');
    expect(eps).toContain('/api/session');
  });

  it('ignores static asset paths', () => {
    const js = `
      fetch('/styles/main.css');
      fetch('/images/logo.png');
      fetch('/fonts/roboto.woff2');
    `;
    const eps = extractEndpoints(js);
    expect(eps).not.toContain('/styles/main.css');
    expect(eps).not.toContain('/images/logo.png');
    expect(eps).not.toContain('/fonts/roboto.woff2');
  });

  it('ignores node_modules paths', () => {
    const js = `import '/node_modules/react/index.js'`;
    const eps = extractEndpoints(js);
    expect(eps.some(e => e.includes('node_modules'))).toBe(false);
  });

  it('ignores too-short paths', () => {
    const js = `fetch('/a')`;
    const eps = extractEndpoints(js);
    expect(eps).not.toContain('/a');
  });

  it('deduplicates identical endpoints', () => {
    const js = `
      fetch('/api/users');
      fetch('/api/users');
      axios.get('/api/users');
    `;
    const eps = extractEndpoints(js);
    const count = eps.filter(e => e === '/api/users').length;
    expect(count).toBe(1);
  });

  it('handles realistic minified JS bundle', () => {
    const js = `var n={get:function(){return fetch("/api/v1/me")},post:function(e){return axios.post("/api/v1/data",e)}};n.open("GET","/v2/health");`;
    const eps = extractEndpoints(js);
    expect(eps).toContain('/api/v1/me');
    expect(eps).toContain('/api/v1/data');
    expect(eps).toContain('/v2/health');
  });
});

// ── extractGraphQL ────────────────────────────────────────────────

describe('extractGraphQL', () => {
  it('extracts query names', () => {
    const js = `
      const q = gql\`
        query GetUsers {
          users { id name }
        }
      \`;
    `;
    const ops = extractGraphQL(js);
    expect(ops).toContain('GetUsers');
  });

  it('extracts mutation names', () => {
    const js = `mutation CreateUser($input: UserInput!) { createUser(input: $input) { id } }`;
    const ops = extractGraphQL(js);
    expect(ops).toContain('CreateUser');
  });

  it('extracts subscription names', () => {
    const js = `subscription OnMessageAdded { messageAdded { id text } }`;
    const ops = extractGraphQL(js);
    expect(ops).toContain('OnMessageAdded');
  });

  it('extracts operationName from request configs', () => {
    const js = `const body = { operationName: "FetchDashboard", query: "..." }`;
    const ops = extractGraphQL(js);
    expect(ops).toContain('FetchDashboard');
  });

  it('extracts operationName from JSON strings', () => {
    const js = `"operationName":"ListProducts"`;
    const ops = extractGraphQL(js);
    expect(ops).toContain('ListProducts');
  });

  it('extracts operations from gql tagged templates', () => {
    const js = `const QUERY = gql\`query SearchItems($term: String!) { search(term: $term) { id } }\``;
    const ops = extractGraphQL(js);
    expect(ops).toContain('SearchItems');
  });

  it('deduplicates operations', () => {
    const js = `
      query GetUsers { users { id } }
      operationName: "GetUsers"
    `;
    const ops = extractGraphQL(js);
    const count = ops.filter(o => o === 'GetUsers').length;
    expect(count).toBe(1);
  });

  it('ignores lowercase names (not GraphQL conventions)', () => {
    const js = `query getUsers { users { id } }`;
    const ops = extractGraphQL(js);
    // Should not match 'getUsers' since our regex requires capital first letter
    expect(ops).not.toContain('getUsers');
  });

  it('handles multiple operations in one string', () => {
    const js = `
      query GetUser { user { id } }
      mutation UpdateUser { updateUser { id } }
      subscription UserChanged { userChanged { id } }
    `;
    const ops = extractGraphQL(js);
    expect(ops).toContain('GetUser');
    expect(ops).toContain('UpdateUser');
    expect(ops).toContain('UserChanged');
  });
});

// ── extractParamNames ─────────────────────────────────────────────

describe('extractParamNames', () => {
  it('extracts URL query parameters', () => {
    const js = `const url = '/search?query=test&limit=10&offset=0';`;
    const params = extractParamNames(js);
    expect(params).toContain('query');
    expect(params).toContain('limit');
    expect(params).toContain('offset');
  });

  it('extracts FormData.append param names', () => {
    const js = `
      formData.append('username', value);
      formData.append('password', secret);
      formData.append('remember_me', 'true');
    `;
    const params = extractParamNames(js);
    expect(params).toContain('username');
    expect(params).toContain('password');
    expect(params).toContain('remember_me');
  });

  it('extracts URLSearchParams method param names', () => {
    const js = `
      searchParams.set('page', '1');
      searchParams.append('sort_by', 'name');
      searchParams.get('filter_type');
      searchParams.has('category_id');
      searchParams.delete('temp_token');
    `;
    const params = extractParamNames(js);
    expect(params).toContain('page');
    expect(params).toContain('sort_by');
    expect(params).toContain('filter_type');
    expect(params).toContain('category_id');
    expect(params).toContain('temp_token');
  });

  it('extracts keys from body/data objects', () => {
    const js = `
      fetch('/api/login', {
        body: { username: user, password: pass, otp_code: code }
      });
    `;
    const params = extractParamNames(js);
    expect(params).toContain('username');
    expect(params).toContain('password');
    expect(params).toContain('otp_code');
  });

  it('extracts keys from data objects', () => {
    const js = `axios.post('/api', { data: { account_id: 123, amount: 50 } })`;
    const params = extractParamNames(js);
    expect(params).toContain('account_id');
    expect(params).toContain('amount');
  });

  it('filters out common JS keywords', () => {
    const js = `body: { function: 1, class: 2, return: 3, async: 4, const: 5 }`;
    const params = extractParamNames(js);
    expect(params).not.toContain('function');
    expect(params).not.toContain('class');
    expect(params).not.toContain('return');
    expect(params).not.toContain('async');
    expect(params).not.toContain('const');
  });

  it('filters out React hooks and DOM properties', () => {
    const js = `body: { useState: x, onClick: fn, className: cls }`;
    const params = extractParamNames(js);
    expect(params).not.toContain('useState');
    expect(params).not.toContain('onClick');
    expect(params).not.toContain('className');
  });

  it('filters out single-character params', () => {
    const js = `?a=1&b=2`;
    const params = extractParamNames(js);
    expect(params).not.toContain('a');
    expect(params).not.toContain('b');
  });

  it('deduplicates param names', () => {
    const js = `
      searchParams.set('page', '1');
      ?page=2
      formData.append('page', '3');
    `;
    const params = extractParamNames(js);
    const count = params.filter(p => p === 'page').length;
    expect(count).toBe(1);
  });
});

// ── extractChunkUrls ──────────────────────────────────────────────

describe('extractChunkUrls', () => {
  const baseUrl = 'https://example.com/static/js/main.js';

  it('extracts webpack chunk filenames', () => {
    const js = `__webpack_require__("vendors.chunk.js")`;
    const chunks = extractChunkUrls(js, baseUrl);
    expect(chunks.some(c => c.includes('vendors.chunk.js'))).toBe(true);
  });

  it('extracts hashed JS filenames', () => {
    const js = `"static/js/123.abc1234f.js"`;
    const chunks = extractChunkUrls(js, baseUrl);
    expect(chunks.some(c => c.includes('abc1234f.js'))).toBe(true);
  });

  it('extracts Vite dynamic imports', () => {
    const js = `import("/assets/module-a1b2c3d4.js")`;
    const chunks = extractChunkUrls(js, baseUrl);
    expect(chunks.some(c => c.includes('/assets/module-a1b2c3d4.js'))).toBe(true);
  });

  it('extracts Next.js chunk URLs', () => {
    const js = `"/_next/static/chunks/pages/index-abc123.js"`;
    const chunks = extractChunkUrls(js, baseUrl);
    expect(chunks.some(c => c.includes('/_next/static/chunks/'))).toBe(true);
  });

  it('resolves relative paths to absolute URLs', () => {
    const js = `"vendors.chunk.js"`;
    const chunks = extractChunkUrls(js, baseUrl);
    for (const chunk of chunks) {
      expect(chunk).toMatch(/^https?:\/\//);
    }
  });

  it('preserves absolute URLs', () => {
    const js = `import("https://cdn.example.com/lib.js")`;
    const chunks = extractChunkUrls(js, baseUrl);
    expect(chunks).toContain('https://cdn.example.com/lib.js');
  });

  it('excludes the base URL itself from results', () => {
    const js = `"${baseUrl}"`;
    const chunks = extractChunkUrls(js, baseUrl);
    expect(chunks).not.toContain(baseUrl);
  });

  it('deduplicates chunk URLs', () => {
    const js = `
      "vendors.chunk.js"
      "vendors.chunk.js"
    `;
    const chunks = extractChunkUrls(js, baseUrl);
    const vendorChunks = chunks.filter(c => c.includes('vendors.chunk.js'));
    expect(vendorChunks.length).toBe(1);
  });

  it('handles hashed references with path prefix', () => {
    const js = `"/static/js/runtime-abc12345678.js"`;
    const chunks = extractChunkUrls(js, baseUrl);
    expect(chunks.some(c => c.includes('runtime-abc12345678.js'))).toBe(true);
  });
});

// ── collectJsUrls ─────────────────────────────────────────────────

describe('collectJsUrls', () => {
  const origin = 'https://example.com';

  it('collects valid JS URLs', () => {
    const scripts = [
      'https://example.com/main.js',
      'https://example.com/vendor.js',
    ];
    const urls = collectJsUrls(scripts, origin);
    expect(urls).toContain('https://example.com/main.js');
    expect(urls).toContain('https://example.com/vendor.js');
  });

  it('filters out tracking/analytics scripts', () => {
    const scripts = [
      'https://example.com/app.js',
      'https://www.google-analytics.com/analytics.js',
      'https://www.googletagmanager.com/gtm.js',
      'https://connect.facebook.net/en_US/fbevents.js',
      'https://cdn.segment.com/analytics.js',
      'https://static.hotjar.com/c/hotjar.js',
      'https://js.sentry-cdn.com/sdk.js',
    ];
    const urls = collectJsUrls(scripts, origin);
    expect(urls).toContain('https://example.com/app.js');
    expect(urls).toHaveLength(1);
  });

  it('filters out non-JS URLs', () => {
    const scripts = [
      'https://example.com/style.css',
      'https://example.com/app.js',
      'https://example.com/image.png',
    ];
    const urls = collectJsUrls(scripts, origin);
    expect(urls).toContain('https://example.com/app.js');
    expect(urls).toHaveLength(1);
  });

  it('filters out data: and blob: URIs', () => {
    const scripts = [
      'data:text/javascript,console.log("hi")',
      'blob:https://example.com/abc-123',
      'https://example.com/real.js',
    ];
    const urls = collectJsUrls(scripts, origin);
    expect(urls).toHaveLength(1);
    expect(urls[0]).toBe('https://example.com/real.js');
  });

  it('deduplicates URLs', () => {
    const scripts = [
      'https://example.com/app.js',
      'https://example.com/app.js',
      'https://example.com/app.js',
    ];
    const urls = collectJsUrls(scripts, origin);
    expect(urls).toHaveLength(1);
  });

  it('prioritizes same-origin scripts', () => {
    const scripts = [
      'https://cdn.other.com/vendor.js',
      'https://example.com/app.js',
      'https://unpkg.com/lib.js',
    ];
    const urls = collectJsUrls(scripts, origin);
    expect(urls[0]).toBe('https://example.com/app.js');
  });

  it('handles empty input', () => {
    const urls = collectJsUrls([], origin);
    expect(urls).toHaveLength(0);
  });

  it('handles .mjs and .cjs extensions', () => {
    const scripts = [
      'https://example.com/module.mjs',
      'https://example.com/common.cjs',
    ];
    const urls = collectJsUrls(scripts, origin);
    expect(urls).toContain('https://example.com/module.mjs');
    expect(urls).toContain('https://example.com/common.cjs');
  });

  it('handles JS URLs with query strings', () => {
    const scripts = [
      'https://example.com/app.js?v=123',
    ];
    const urls = collectJsUrls(scripts, origin);
    expect(urls).toHaveLength(1);
    expect(urls[0]).toBe('https://example.com/app.js?v=123');
  });

  it('skips empty strings and falsy values', () => {
    const scripts = ['', 'https://example.com/app.js'];
    const urls = collectJsUrls(scripts, origin);
    expect(urls).toHaveLength(1);
  });
});

// ── Integration-style: realistic JS bundle content ────────────────

describe('realistic JS analysis', () => {
  it('extracts full attack surface from a Next.js bundle', () => {
    const nextJsBundle = `
      !function(){var e={};e.p="/_next/static/";
      fetch("/api/auth/session");
      fetch("/api/v1/users",{method:"POST",body:JSON.stringify({email:e,password:p,remember_me:true})});
      axios.get("/api/v1/products?category_id=1&sort=price");
      var q=gql\`query GetDashboard { dashboard { stats { revenue users } } }\`;
      var m=gql\`mutation UpdateProfile($input: ProfileInput!) { updateProfile(input: $input) { id } }\`;
      "/_next/static/chunks/pages/dashboard-a1b2c3d4e5f6g7h8.js"
      "/_next/static/chunks/framework-abc123def456.js"
      import("/_next/static/chunks/lazy-component-12345678.js");
      searchParams.set('redirect_uri', url);
      formData.append('csrf_token', token);
      searchParams.get('access_token');
    `;

    const endpoints = extractEndpoints(nextJsBundle);
    expect(endpoints).toContain('/api/auth/session');
    expect(endpoints).toContain('/api/v1/users');
    expect(endpoints).toContain('/api/v1/products?category_id=1&sort=price');

    const graphql = extractGraphQL(nextJsBundle);
    expect(graphql).toContain('GetDashboard');
    expect(graphql).toContain('UpdateProfile');

    const params = extractParamNames(nextJsBundle);
    expect(params).toContain('email');
    expect(params).toContain('password');
    expect(params).toContain('remember_me');
    expect(params).toContain('category_id');
    expect(params).toContain('redirect_uri');
    expect(params).toContain('csrf_token');
    expect(params).toContain('access_token');

    const chunks = extractChunkUrls(nextJsBundle, 'https://example.com/_next/static/js/main.js');
    expect(chunks.some(c => c.includes('dashboard-a1b2c3d4e5f6g7h8.js'))).toBe(true);
    expect(chunks.some(c => c.includes('framework-abc123def456.js'))).toBe(true);
    expect(chunks.some(c => c.includes('lazy-component-12345678.js'))).toBe(true);
  });

  it('extracts attack surface from a React SPA with axios', () => {
    const reactSpa = `
      const api=axios.create({baseURL:"/api/v2"});
      api.interceptors.request.use(function(e){return e.headers.Authorization="Bearer "+t,e});
      router.get("/admin/users", adminHandler);
      router.post("/admin/settings", settingsHandler);
      app.delete("/api/v2/sessions/:id", deleteSession);
      var config={url:"/api/v2/config",method:"GET"};
      fetch("https://api.stripe.com/v1/charges");
    `;

    const endpoints = extractEndpoints(reactSpa);
    expect(endpoints).toContain('/admin/users');
    expect(endpoints).toContain('/admin/settings');
    expect(endpoints).toContain('/api/v2/sessions/:id');
    expect(endpoints).toContain('/api/v2/config');
    expect(endpoints).toContain('https://api.stripe.com/v1/charges');
  });

  it('extracts attack surface from a Vite/Vue app', () => {
    const vueApp = `
      import("/assets/AdminPanel-b2c3d4e5.js")
      import("/assets/UserSettings-a1b2c3d4.js")
      fetch('/api/graphql',{method:'POST',body:JSON.stringify({operationName:"GetUserProfile",query:q})})
      subscription OnOrderUpdate { orderUpdate { id status } }
    `;

    const endpoints = extractEndpoints(vueApp);
    expect(endpoints).toContain('/api/graphql');

    const graphql = extractGraphQL(vueApp);
    expect(graphql).toContain('GetUserProfile');
    expect(graphql).toContain('OnOrderUpdate');

    const chunks = extractChunkUrls(vueApp, 'https://example.com/assets/main.js');
    expect(chunks.some(c => c.includes('AdminPanel'))).toBe(true);
    expect(chunks.some(c => c.includes('UserSettings'))).toBe(true);
  });
});
