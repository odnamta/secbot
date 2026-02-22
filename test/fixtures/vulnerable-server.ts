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
    <li><a href="/login">Login Form</a></li>
    <li><a href="/api/v1/users/1">User API (IDOR)</a></li>
    <li><a href="/api/v1/data?query=test">Data API (SQLi)</a></li>
    <li><a href="/redirect?url=https://example.com">Open Redirect</a></li>
    <li><a href="/files?path=etc/passwd">Directory Traversal</a></li>
    <li><a href="/fetch?url=http://example.com">SSRF</a></li>
    <li><a href="/template?name=World">SSTI</a></li>
    <li><a href="/exec?cmd=whoami">Command Injection</a></li>
    <li><a href="/cors-api">CORS Misconfiguration</a></li>
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

  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const addr = server.address();
      const port = typeof addr === 'object' && addr !== null ? addr.port : 0;
      const url = `http://127.0.0.1:${port}`;
      resolve({ server, url });
    });
  });
}
