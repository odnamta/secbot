import express from 'express';
import { execSync } from 'node:child_process';
import type { Server } from 'node:http';

export async function createVulnerableServer(): Promise<{ server: Server; url: string }> {
  const app = express();
  app.use(express.urlencoded({ extended: true }));
  app.use(express.json());

  // Set insecure cookies on every response (except /safe)
  app.use((req, res, next) => {
    if (req.path !== '/safe') {
      // auth_token cookie: no HttpOnly flag
      res.setHeader('Set-Cookie', [
        'auth_token=abc; Path=/',
        'session=xyz; HttpOnly; Path=/',
      ]);
    }
    next();
  });

  // Homepage — links to all test pages, no security headers
  app.get('/', (_req, res) => {
    res.type('html').send(`<!DOCTYPE html>
<html>
<head><title>Vulnerable Test Server</title></head>
<body>
  <h1>Vulnerable Test Server</h1>
  <script src="https://cdn.example.com/lib.js"></script>
  <link rel="stylesheet" href="https://cdn.example.com/style.css">
  <ul>
    <li><a href="/search?q=test">Search (XSS)</a></li>
    <li><a href="/spa-search?q=test">SPA Search (DOM XSS)</a></li>
    <li><a href="/spa-search-safe?q=test">SPA Search Safe</a></li>
    <li><a href="/login">Login Form</a></li>
    <li><a href="/api/v1/users/1">User API (IDOR)</a></li>
    <li><a href="/api/v1/data?query=test">Data API (SQLi)</a></li>
    <li><a href="/redirect?url=https://example.com">Open Redirect</a></li>
    <li><a href="/redirect-to?to=https://github.com/juice-shop/juice-shop">Open Redirect (to param)</a></li>
    <li><a href="/safe-redirect?to=https://example.com">Safe Redirect</a></li>
    <li><a href="/files?path=etc/passwd">Directory Traversal</a></li>
    <li><a href="/fetch?url=http://example.com">SSRF</a></li>
    <li><a href="/template?name=World">SSTI</a></li>
    <li><a href="/exec?cmd=whoami">Command Injection</a></li>
    <li><a href="/cors-api">CORS Misconfiguration</a></li>
    <li><a href="/feedback">Feedback Form (POST XSS)</a></li>
    <li><a href="/api/v1/comments">Comments API (JSON XSS)</a></li>
    <li><a href="/login-vuln">Login (POST SQLi)</a></li>
    <li><a href="/api/v1/search">Search API (JSON SQLi)</a></li>
    <li><a href="/api/crlf-redirect?url=https://example.com">CRLF Redirect</a></li>
    <li><a href="/api/crlf-header?name=test">CRLF Header</a></li>
    <li><a href="/safe">Safe Page</a></li>
  </ul>
</body>
</html>`);
  });

  // Reflected XSS — no encoding, directly embeds q in HTML
  app.get('/search', (req, res) => {
    const q = req.query.q as string || '';
    res.type('html').send(`<!DOCTYPE html>
<html>
<head><title>Search Results</title></head>
<body>
  <h1>Search Results for: ${q}</h1>
  <p>No results found for ${q}</p>
</body>
</html>`);
  });

  // SPA-like search — simulates Angular/React SPA that fetches data and renders via innerHTML
  // The server returns a page with JS that fetches search results and renders them unsafely
  app.get('/spa-search', (req, res) => {
    const q = req.query.q as string || '';
    res.type('html').send(`<!DOCTYPE html>
<html>
<head><title>SPA Search</title></head>
<body>
  <h1>SPA Search</h1>
  <div id="results">Loading...</div>
  <script>
    // Simulate SPA behavior: read query param and render via innerHTML (unsafe)
    const params = new URLSearchParams(window.location.search);
    const query = params.get('q') || '';
    // Simulate API response rendering — directly sets innerHTML (DOM XSS)
    document.getElementById('results').innerHTML = '<p>Search results for: ' + query + '</p><p>No results found.</p>';
  </script>
</body>
</html>`);
  });

  // Safe SPA search — properly encodes output
  app.get('/spa-search-safe', (req, res) => {
    res.type('html').send(`<!DOCTYPE html>
<html>
<head><title>SPA Search Safe</title></head>
<body>
  <h1>SPA Search</h1>
  <div id="results">Loading...</div>
  <script>
    const params = new URLSearchParams(window.location.search);
    const query = params.get('q') || '';
    // Safe: uses textContent instead of innerHTML
    const div = document.getElementById('results');
    const p = document.createElement('p');
    p.textContent = 'Search results for: ' + query;
    div.innerHTML = '';
    div.appendChild(p);
  </script>
</body>
</html>`);
  });

  // Login form
  app.get('/login', (_req, res) => {
    res.type('html').send(`<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
  <h1>Login</h1>
  <form method="POST" action="/login">
    <label for="username">Username:</label>
    <input type="text" id="username" name="username" />
    <label for="password">Password:</label>
    <input type="password" id="password" name="password" />
    <button type="submit">Login</button>
  </form>
</body>
</html>`);
  });

  app.post('/login', (req, res) => {
    res.type('html').send(`<!DOCTYPE html>
<html><body><p>Login attempt for user: ${req.body?.username}</p></body></html>`);
  });

  // IDOR — sequential user IDs
  app.get('/api/v1/users/:id', (req, res) => {
    const id = parseInt(req.params.id, 10);
    const users: Record<number, { id: number; name: string; email: string; role: string }> = {
      1: { id: 1, name: 'Alice Admin', email: 'alice@example.com', role: 'admin' },
      2: { id: 2, name: 'Bob User', email: 'bob@example.com', role: 'user' },
      3: { id: 3, name: 'Charlie Manager', email: 'charlie@example.com', role: 'manager' },
    };
    const user = users[id];
    if (user) {
      res.json(user);
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  });

  // SQLi error reflection
  app.get('/api/v1/data', (req, res) => {
    const query = req.query.query as string || '';
    if (query.includes("'")) {
      res.type('html').status(500).send(`<!DOCTYPE html>
<html><body>
<h1>Internal Server Error</h1>
<p>SQL Error: You have an error in your SQL syntax near '${query}' at line 1</p>
</body></html>`);
    } else {
      res.json({ results: [], query });
    }
  });

  // Open redirect
  app.get('/redirect', (req, res) => {
    const url = req.query.url as string || '/';
    res.redirect(302, url);
  });

  // Open redirect via "to" parameter (simulates Juice Shop /redirect?to=...)
  app.get('/redirect-to', (req, res) => {
    const to = req.query.to as string || '/';
    res.redirect(302, to);
  });

  // Safe redirect — only allows whitelisted domains (properly secured)
  app.get('/safe-redirect', (req, res) => {
    const to = req.query.to as string || '/';
    const ALLOWED_HOSTS = ['example.com', 'www.example.com'];

    // Block protocol-relative URLs and backslash tricks
    if (/^\/[\/\\]/.test(to) || /^[a-z]+:/i.test(to)) {
      try {
        const parsed = new URL(to, 'http://localhost');
        if (ALLOWED_HOSTS.includes(parsed.hostname)) {
          res.redirect(302, to);
        } else {
          res.status(400).send('Redirect to external domain not allowed');
        }
      } catch {
        res.status(400).send('Invalid redirect URL');
      }
      return;
    }

    // Relative paths starting with single / are safe
    if (to.startsWith('/')) {
      res.redirect(302, to);
      return;
    }

    // Anything else (no leading /) — reject
    res.status(400).send('Invalid redirect URL');
  });

  // Directory traversal
  app.get('/files', (req, res) => {
    const path = req.query.path as string || '';
    // Intentionally vulnerable — no path sanitization
    res.type('html').send(`<!DOCTYPE html>
<html><body>
<h1>File Viewer</h1>
<pre>Contents of ${path}:\n\nroot:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin</pre>
</body></html>`);
  });

  // SSRF endpoint
  app.get('/fetch', async (req, res) => {
    const url = req.query.url as string || '';
    if (!url) {
      res.status(400).json({ error: 'url parameter required' });
      return;
    }
    try {
      const response = await fetch(url);
      const text = await response.text();
      res.type('html').send(`<!DOCTYPE html>
<html><body>
<h1>Fetched URL: ${url}</h1>
<pre>${text.substring(0, 1000)}</pre>
</body></html>`);
    } catch (err) {
      res.type('html').send(`<!DOCTYPE html>
<html><body>
<h1>Fetch Error</h1>
<p>Could not fetch ${url}: ${(err as Error).message}</p>
</body></html>`);
    }
  });

  // SSTI — evaluates template expressions
  app.get('/template', (req, res) => {
    let name = req.query.name as string || 'World';
    // Intentionally vulnerable template evaluation
    // Handle numeric multiplication: {{71829*71829}} → 5159404241
    name = name.replace(/\{\{(\d+)\*(\d+)\}\}/g, (_match, a, b) => {
      return String(BigInt(a) * BigInt(b));
    });
    // Handle string multiplication: {{8*'71829'}} → '71829' repeated 8 times
    name = name.replace(/\{\{(\d+)\*'(\d+)'\}\}/g, (_match, count, str) => {
      return str.repeat(Number(count));
    });
    // Handle addition: {{71829+71829}} → 143658
    name = name.replace(/\{\{(\d+)\+(\d+)\}\}/g, (_match, a, b) => {
      return String(BigInt(a) + BigInt(b));
    });
    res.type('html').send(`<!DOCTYPE html>
<html><body>
<h1>Hello, ${name}!</h1>
</body></html>`);
  });

  // Command injection — actually executes commands (test fixture only!)
  app.get('/exec', (req, res) => {
    const cmd = req.query.cmd as string || '';
    let output = '';
    try {
      output = execSync(cmd, { timeout: 5000, encoding: 'utf-8' });
    } catch (err) {
      output = (err as Error).message;
    }
    res.type('html').send(`<!DOCTYPE html>
<html><body>
<h1>Command Output</h1>
<pre>$ ${cmd}\n${output}</pre>
</body></html>`);
  });

  // CORS misconfiguration
  app.get('/cors-api', (_req, res) => {
    res.set('Access-Control-Allow-Origin', '*');
    res.set('Access-Control-Allow-Credentials', 'true');
    res.json({ secret: 'sensitive-data', apiKey: 'sk-12345' });
  });

  // POST form that reflects body params (XSS via POST body)
  app.get('/feedback', (_req, res) => {
    res.type('html').send(`<!DOCTYPE html>
<html>
<head><title>Feedback</title></head>
<body>
  <h1>Submit Feedback</h1>
  <form method="POST" action="/feedback">
    <label for="name">Name:</label>
    <input type="text" id="name" name="name" />
    <label for="message">Message:</label>
    <input type="text" id="message" name="message" />
    <button type="submit">Submit</button>
  </form>
</body>
</html>`);
  });

  app.post('/feedback', (req, res) => {
    const name = req.body?.name || '';
    const message = req.body?.message || '';
    res.type('html').send(`<!DOCTYPE html>
<html><body>
<h1>Thank you, ${name}!</h1>
<p>Your feedback: ${message}</p>
</body></html>`);
  });

  // JSON API that echoes input without encoding (stored XSS via API)
  app.post('/api/v1/comments', (req, res) => {
    const { author, text } = req.body || {};
    // Intentionally echoes back unencoded in a JSON response
    res.json({
      id: 42,
      author: author || 'anonymous',
      text: text || '',
      createdAt: new Date().toISOString(),
    });
  });

  // JSON API that renders echoed data in HTML (the real danger: stored XSS)
  app.get('/api/v1/comments/render', (req, res) => {
    const text = req.query.text as string || '';
    res.type('html').send(`<!DOCTYPE html>
<html><body>
<div class="comment">${text}</div>
</body></html>`);
  });

  // JSON API endpoint that accepts PUT and echoes JSON values
  app.put('/api/v1/profile', (req, res) => {
    const { displayName, bio } = req.body || {};
    res.json({
      success: true,
      profile: {
        displayName: displayName || '',
        bio: bio || '',
      },
    });
  });

  // Safe JSON API — properly encodes output
  app.post('/api/v1/safe-comments', (req, res) => {
    const { author, text } = req.body || {};
    const encode = (s: string) => s.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    res.json({
      id: 43,
      author: encode(author || 'anonymous'),
      text: encode(text || ''),
      createdAt: new Date().toISOString(),
    });
  });

  // ─── SQLi via POST form (vulnerable login) ───
  // The /login-vuln GET page renders a form that POSTs to /api/v1/login
  app.get('/login-vuln', (_req, res) => {
    res.type('html').send(`<!DOCTYPE html>
<html>
<head><title>Login (Vulnerable)</title></head>
<body>
  <h1>Login</h1>
  <form method="POST" action="/api/v1/login">
    <label for="username">Username:</label>
    <input type="text" id="username" name="username" />
    <label for="password">Password:</label>
    <input type="password" id="password" name="password" />
    <button type="submit">Login</button>
  </form>
</body>
</html>`);
  });

  // POST form endpoint vulnerable to SQLi — concatenates username into SQL
  app.post('/api/v1/login', (req, res) => {
    const username = req.body?.username || '';
    if (username.includes("'")) {
      res.type('html').status(500).send(`<!DOCTYPE html>
<html><body>
<h1>Internal Server Error</h1>
<p>SQL Error: You have an error in your SQL syntax near '${username}' at line 1</p>
</body></html>`);
    } else {
      res.type('html').send(`<!DOCTYPE html>
<html><body><p>Login attempt for user: ${username}</p></body></html>`);
    }
  });

  // ─── SQLi via JSON API body (vulnerable search) ───
  app.post('/api/v1/search', (req, res) => {
    const query = req.body?.query || '';
    if (typeof query === 'string' && query.includes("'")) {
      res.status(500).json({
        error: true,
        message: `SQL Error: You have an error in your SQL syntax near '${query}' at line 1`,
      });
    } else {
      res.json({ results: [], query });
    }
  });

  // ─── JWT endpoint (returns a weak-secret JWT with no expiry) ───
  app.get('/api/v1/token', (_req, res) => {
    const { createHmac } = require('node:crypto');
    const header = Buffer.from(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
      .toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const payload = Buffer.from(JSON.stringify({ sub: '1234', role: 'user', name: 'Test User' }))
      .toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const sig = createHmac('sha256', 'secret')
      .update(`${header}.${payload}`)
      .digest()
      .toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const token = `${header}.${payload}.${sig}`;
    res.json({ access_token: token, token_type: 'Bearer' });
  });

  // JSON API endpoint that is NOT vulnerable to SQLi (safe search)
  app.post('/api/v1/safe-search', (req, res) => {
    const query = req.body?.query || '';
    // Uses parameterized queries (simulated) — always returns safe response
    res.json({ results: [], query: 'sanitized' });
  });

  // Safe page — properly secured
  app.get('/safe', (_req, res) => {
    res.set('Content-Security-Policy', "default-src 'self'");
    res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.set('X-Frame-Options', 'DENY');
    res.set('X-Content-Type-Options', 'nosniff');
    res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    // Override cookies with secure versions on /safe
    res.setHeader('Set-Cookie', [
      'auth_token=abc; Path=/; HttpOnly; Secure; SameSite=Strict',
      'session=xyz; Path=/; HttpOnly; Secure; SameSite=Strict',
    ]);
    const name = 'User <script>alert(1)</script>';
    const encoded = name.replace(/</g, '&lt;').replace(/>/g, '&gt;');
    res.type('html').send(`<!DOCTYPE html>
<html><body>
<h1>Safe Page</h1>
<p>Hello, ${encoded}</p>
</body></html>`);
  });

  // ─── CRLF Injection Endpoints ───────────────────────────────────────
  // Vulnerable: writes raw HTTP response to bypass Node.js header sanitization.
  // This simulates a server that does not sanitize CRLF in header values.
  app.get('/api/crlf-redirect', (req, res) => {
    const url = req.query.url as string || '/';
    // Bypass Node.js header protection by writing raw HTTP via socket
    const socket = res.socket;
    if (!socket || socket.destroyed) { res.status(500).end(); return; }
    const rawResponse = `HTTP/1.1 302 Found\r\nLocation: ${url}\r\nConnection: close\r\n\r\n`;
    socket.write(rawResponse);
    socket.end();
  });

  // Vulnerable: writes raw HTTP response with custom header using unsanitized param
  app.get('/api/crlf-header', (req, res) => {
    const name = req.query.name as string || 'default';
    const body = `<!DOCTYPE html>\n<html><body>\n<h1>Header Echo</h1>\n<p>Name: ${name}</p>\n</body></html>`;
    const socket = res.socket;
    if (!socket || socket.destroyed) { res.status(500).end(); return; }
    const rawResponse = `HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nX-Custom-Name: ${name}\r\nConnection: close\r\n\r\n${body}`;
    socket.write(rawResponse);
    socket.end();
  });

  // Safe CRLF endpoint — sanitizes CRLF characters before using in headers
  app.get('/api/crlf-safe', (req, res) => {
    const url = req.query.url as string || '/';
    // Sanitize: strip all \r and \n characters
    const sanitized = url.replace(/[\r\n]/g, '');
    // Even with raw socket, sanitized value is safe
    const socket = res.socket;
    if (!socket || socket.destroyed) { res.status(500).end(); return; }
    const rawResponse = `HTTP/1.1 302 Found\r\nLocation: ${sanitized}\r\nConnection: close\r\n\r\n`;
    socket.write(rawResponse);
    socket.end();
  });

  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
      const url = `http://127.0.0.1:${port}`;
      resolve({ server, url });
    });
  });
}
