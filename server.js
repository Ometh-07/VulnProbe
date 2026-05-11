'use strict';

require('dotenv').config(); // Load environment variables

const express = require('express');
const cors    = require('cors');
const fetch   = require('node-fetch');
const https   = require('https');
const cheerio = require('cheerio');
const { URL } = require('url');
const path    = require('path');
const { getDatabase } = require('./db');

const app  = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Serve index.html at root
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ─── helpers ──────────────────────────────────────────────────────────────────

const insecureAgent = new https.Agent({ rejectUnauthorized: false });

function makeAgent(protocol) {
  return protocol === 'https:' ? insecureAgent : undefined;
}

async function safeFetch(url, baseOpts = {}, extraOpts = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  try {
    const parsed   = new URL(url);
    const agent    = makeAgent(parsed.protocol);
    const response = await fetch(url, {
      agent,
      signal: controller.signal,
      headers: {
        'User-Agent': 'RabbitHunt/1.0 Security Scanner',
        Accept: '*/*',
      },
      redirect: 'manual',
      ...baseOpts,
      ...extraOpts,
    });
    clearTimeout(timer);
    return response;
  } catch {
    clearTimeout(timer);
    return null;
  }
}

// Read full body with a size cap so we don't OOM on huge responses
async function safeText(res, maxBytes = 500_000) {
  try {
    const buf = await res.buffer();
    return buf.slice(0, maxBytes).toString('utf8');
  } catch {
    return '';
  }
}

// ─── SSE scan endpoint ────────────────────────────────────────────────────────

app.get('/api/scan', async (req, res) => {
  const { url: targetUrl, types } = req.query;

  const scanTypes = types
    ? types.split(',').map(t => t.trim())
    : ['headers', 'misconfig', 'xss', 'sqli', 'auth', 'csrf'];

  res.setHeader('Content-Type',  'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection',    'keep-alive');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.flushHeaders();

  const send = data => res.write(`data: ${JSON.stringify(data)}\n\n`);

  const log = (text, color = '#b0ffa0') => send({ type: 'log', text, color });
  const finding  = vuln  => send({ type: 'finding', vuln });
  const progress = (pct, phase) => send({ type: 'progress', progress: pct, phase });

  // ─── Validate URL ──────────────────────────────────────────────────────────

  let parsed;
  try {
    parsed = new URL(targetUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error();
  } catch {
    send({ type: 'error', message: 'Invalid URL. Use http:// or https://' });
    return res.end();
  }

  const baseUrl = `${parsed.protocol}//${parsed.host}`;
  let vulnId = 1;

  try {
    log(`$ vulnprobe --target ${targetUrl} --modules ${scanTypes.join(',')}`, '#7F77DD');
    log('[*] VulnProbe v1.0.0 — Initialising security assessment', '#888');
    progress(5, 'Connecting to target...');

    // ─── Initial connection ────────────────────────────────────────────────────

    const mainRes = await safeFetch(targetUrl);
    if (!mainRes) {
      send({ type: 'error', message: `Cannot reach ${targetUrl}. Verify the URL is accessible.` });
      return res.end();
    }

    const mainBody    = await safeText(mainRes);
    const resHeaders  = mainRes.headers;

    log(`[*] Connected — HTTP ${mainRes.status} ${mainRes.statusText || 'OK'}`, '#aaa');
    log(`[*] Response size: ${mainBody.length.toLocaleString()} bytes`, '#666');

    // ─── 1. Security headers ───────────────────────────────────────────────────

    if (scanTypes.includes('headers')) {
      progress(12, 'Analysing security headers...');
      log('[*] Checking HTTP security headers...', '#aaa');

      const checks = [
        { header: 'content-security-policy',   label: 'Content-Security-Policy',   sev: 'High'   },
        { header: 'strict-transport-security',  label: 'Strict-Transport-Security', sev: 'Medium' },
        { header: 'x-frame-options',            label: 'X-Frame-Options',           sev: 'Medium' },
        { header: 'x-content-type-options',     label: 'X-Content-Type-Options',    sev: 'Low'    },
        { header: 'referrer-policy',            label: 'Referrer-Policy',           sev: 'Low'    },
        { header: 'permissions-policy',         label: 'Permissions-Policy',        sev: 'Low'    },
      ];

      const missing = checks.filter(c => !resHeaders.get(c.header));

      if (missing.length > 0) {
        const worstSev = missing.some(c => c.sev === 'High')
          ? 'High'
          : missing.some(c => c.sev === 'Medium') ? 'Medium' : 'Low';

        log(`[!] Missing headers: ${missing.map(c => c.label).join(', ')}`, '#44ff99');
        finding({
          id: vulnId++, type: 'headers', severity: worstSev,
          url: '/', param: '-',
          detail: `Missing security headers: ${missing.map(c => c.label).join(', ')}. These headers protect against clickjacking, MIME-sniffing, and XSS.`,
          remediation: 'Add the missing headers in your web server config (nginx/Apache) or application middleware. For Node/Express use helmet: app.use(require("helmet")()).',
        });
      } else {
        log('[✓] All standard security headers present', '#44ff99');
      }

      // Server / technology disclosure
      const serverHdr    = resHeaders.get('server') || '';
      const poweredByHdr = resHeaders.get('x-powered-by') || '';

      if (serverHdr && /\d/.test(serverHdr)) {
        log(`[!] Server version disclosed: ${serverHdr}`, '#ffbb00');
        finding({
          id: vulnId++, type: 'misconfig', severity: 'Low',
          url: '/', param: 'Server',
          detail: `Server header leaks version info: "${serverHdr}". Attackers can look up CVEs for this exact version.`,
          remediation: 'Suppress or genericise the Server header in your web server configuration.',
        });
      }

      if (poweredByHdr) {
        log(`[!] X-Powered-By disclosed: ${poweredByHdr}`, '#ffbb00');
        finding({
          id: vulnId++, type: 'misconfig', severity: 'Low',
          url: '/', param: 'X-Powered-By',
          detail: `Technology stack disclosed: "${poweredByHdr}". This helps attackers fingerprint the application.`,
          remediation: 'Remove X-Powered-By. In Express: app.disable("x-powered-by"). In PHP: expose_php = Off.',
        });
      }
    }

    // ─── 2. Misconfiguration ───────────────────────────────────────────────────

    if (scanTypes.includes('misconfig')) {
      progress(25, 'Checking for misconfigurations...');
      log('[*] Probing for common misconfigurations...', '#aaa');

      // HTTPS enforcement
      if (parsed.protocol === 'http:') {
        const httpsRes = await safeFetch(`https://${parsed.host}${parsed.pathname}`);
        if (!httpsRes || httpsRes.status >= 400) {
          log('[!] HTTPS not available or not enforced', '#ff9900');
          finding({
            id: vulnId++, type: 'misconfig', severity: 'High',
            url: parsed.pathname || '/', param: 'Protocol',
            detail: 'Site is served over HTTP with no HTTPS equivalent. All traffic is plaintext and can be intercepted or tampered with (MITM attacks).',
            remediation: 'Obtain an SSL/TLS certificate (free via Let\'s Encrypt) and configure a 301 redirect from HTTP to HTTPS. Add HSTS header.',
          });
        } else {
          log('[✓] HTTPS endpoint found', '#44ff99');
        }
      }

      // CORS misconfiguration
      const corsRes = await safeFetch(targetUrl, {}, {
        headers: {
          'User-Agent': 'RabbitHunt/1.0 Security Scanner',
          Origin: 'https://evil-attacker.example.com',
        },
      });
      if (corsRes) {
        const acao = corsRes.headers.get('access-control-allow-origin') || '';
        if (acao === '*' || acao === 'https://evil-attacker.example.com') {
          log(`[!] Overly permissive CORS: ACAO: ${acao}`, '#ff9900');
          finding({
            id: vulnId++, type: 'misconfig', severity: 'High',
            url: '/', param: 'Access-Control-Allow-Origin',
            detail: `CORS is set to "${acao}" — any external site can read authenticated responses from this API, enabling cross-origin data theft.`,
            remediation: 'Restrict Access-Control-Allow-Origin to your specific trusted domains. Never use wildcard (*) on endpoints that use cookies or carry sensitive data.',
          });
        }
      }

      // Sensitive path probing
      const sensitivePaths = [
        { p: '/.git/HEAD',      label: 'Git repository',        sev: 'Critical' },
        { p: '/.env',           label: '.env secrets file',      sev: 'Critical' },
        { p: '/phpinfo.php',    label: 'phpinfo() page',         sev: 'High'     },
        { p: '/.DS_Store',      label: '.DS_Store (macOS meta)', sev: 'Medium'   },
        { p: '/admin',          label: 'Admin panel',            sev: 'Medium'   },
        { p: '/wp-admin/',      label: 'WordPress admin',        sev: 'Medium'   },
        { p: '/backup',         label: 'Backup directory',       sev: 'High'     },
        { p: '/config.php',     label: 'PHP config file',        sev: 'High'     },
        { p: '/server-status',  label: 'Apache server-status',   sev: 'Medium'   },
        { p: '/server-info',    label: 'Apache server-info',     sev: 'Medium'   },
        { p: '/.htaccess',      label: '.htaccess file',         sev: 'Medium'   },
        { p: '/web.config',     label: 'IIS web.config',         sev: 'High'     },
        { p: '/dump.sql',       label: 'SQL dump file',          sev: 'Critical' },
        { p: '/database.sql',   label: 'SQL dump file',          sev: 'Critical' },
      ];

      for (const sp of sensitivePaths) {
        const r = await safeFetch(`${baseUrl}${sp.p}`);
        if (r && r.status === 200) {
          const body = await safeText(r, 5000);
          const looksReal =
            body.length > 10 &&
            !/not found/i.test(body.slice(0, 300)) &&
            !/<title>[^<]*404/i.test(body.slice(0, 500));

          if (looksReal) {
            log(`[!] Sensitive path accessible: ${sp.p} (200)`, '#ff4444');
            finding({
              id: vulnId++, type: 'misconfig', severity: sp.sev,
              url: sp.p, param: '-',
              detail: `${sp.label} is publicly accessible at ${sp.p}. This can expose credentials, source code, or configuration data.`,
              remediation: `Block access to "${sp.p}" via your web server configuration, or remove the file from the server entirely.`,
            });
          }
        }
      }

      // Directory listing
      const dirPaths = ['/images/', '/uploads/', '/static/', '/assets/', '/files/'];
      for (const dp of dirPaths) {
        const dr = await safeFetch(`${baseUrl}${dp}`);
        if (dr && dr.status === 200) {
          const body = await safeText(dr, 10000);
          if (/Index of\s+\//i.test(body) || /\bDirectory listing\b/i.test(body)) {
            log(`[!] Directory listing enabled at ${dp}`, '#ff9900');
            finding({
              id: vulnId++, type: 'misconfig', severity: 'Medium',
              url: dp, param: '-',
              detail: `Directory listing is enabled at "${dp}". Attackers can enumerate all files in this directory.`,
              remediation: 'Disable directory listing: Apache: Options -Indexes, Nginx: add "autoindex off;" in the location block.',
            });
            break;
          }
        }
      }

      log('[*] Misconfiguration check complete', '#aaa');
    }

    // ─── 3. Authentication & session security ──────────────────────────────────

    if (scanTypes.includes('auth')) {
      progress(42, 'Auditing authentication & cookies...');
      log('[*] Analysing authentication and session security...', '#aaa');

      // Cookie flags
      const rawCookies = resHeaders.raw ? (resHeaders.raw()['set-cookie'] || []) : [];
      const cookieStr  = resHeaders.get('set-cookie') || '';
      const allCookies = rawCookies.length ? rawCookies : (cookieStr ? [cookieStr] : []);

      for (const ck of allCookies) {
        const isSession = /session|sess|sid|auth|token/i.test(ck);
        if (!isSession) continue;

        if (!/HttpOnly/i.test(ck)) {
          log('[!] Session cookie missing HttpOnly flag', '#ffcc00');
          finding({
            id: vulnId++, type: 'auth', severity: 'Medium',
            url: '/', param: 'Set-Cookie',
            detail: 'A session-like cookie is missing the HttpOnly flag. JavaScript (e.g. via XSS) can read it with document.cookie.',
            remediation: 'Set HttpOnly on all authentication cookies: Set-Cookie: session=abc; HttpOnly; Secure; SameSite=Strict',
          });
        }

        if (!/;\s*Secure/i.test(ck)) {
          log('[!] Session cookie missing Secure flag', '#ffcc00');
          finding({
            id: vulnId++, type: 'auth', severity: 'Medium',
            url: '/', param: 'Set-Cookie',
            detail: 'A session cookie lacks the Secure flag and can be transmitted over plain HTTP, exposing it to interception.',
            remediation: 'Add the Secure attribute to all session cookies to enforce HTTPS-only transmission.',
          });
        }

        if (!/SameSite/i.test(ck)) {
          finding({
            id: vulnId++, type: 'auth', severity: 'Low',
            url: '/', param: 'Set-Cookie',
            detail: 'A session cookie is missing the SameSite attribute, making it more vulnerable to CSRF attacks.',
            remediation: 'Add SameSite=Strict (or at least SameSite=Lax) to all session cookies.',
          });
        }
      }

      // Inspect login form on the page
      const $doc = cheerio.load(mainBody);
      const passwordInputs = $doc('input[type="password"]');

      if (passwordInputs.length > 0) {
        log('[*] Login form detected — checking field attributes...', '#aaa');

        passwordInputs.each((_, el) => {
          const ac = $doc(el).attr('autocomplete') || '';
          if (!['off', 'new-password', 'current-password'].includes(ac.toLowerCase())) {
            finding({
              id: vulnId++, type: 'auth', severity: 'Low',
              url: parsed.pathname || '/', param: 'password',
              detail: 'Password field does not explicitly disable autocomplete. Browsers may cache passwords on shared devices.',
              remediation: 'Add autocomplete="off" or autocomplete="current-password" to password input elements.',
            });
          }
        });

        // Check if form uses HTTPS action
        $doc('form').each((_, form) => {
          const $form  = $doc(form);
          const action = $form.attr('action') || '';
          if (action.startsWith('http:')) {
            finding({
              id: vulnId++, type: 'auth', severity: 'High',
              url: parsed.pathname || '/', param: 'form action',
              detail: `Form submits credentials to an HTTP URL: "${action}". Passwords will be sent unencrypted.`,
              remediation: 'Ensure all form actions use HTTPS URLs.',
            });
          }
        });
      }

      log('[*] Auth/session check complete', '#aaa');
    }

    // ─── 4. XSS — reflection test ─────────────────────────────────────────────

    if (scanTypes.includes('xss')) {
      progress(58, 'Testing for reflected XSS...');
      log('[*] Probing for reflected XSS...', '#aaa');

      const marker   = `rbht${Date.now().toString(36)}`;
      const payloads = [
        `<${marker}>`,
        `"><${marker}>`,
        `'><${marker}>`,
        `javascript:${marker}`,
      ];
      const testParams = ['q', 'search', 'query', 'keyword', 'term', 'id', 'name', 'input', 'text', 'msg', 's'];
      let xssFound = false;

      outer: for (const param of testParams) {
        for (const payload of payloads) {
          const testUrl = `${targetUrl}${targetUrl.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(payload)}`;
          const r = await safeFetch(testUrl);
          if (!r) continue;

          const body = await safeText(r, 200_000);
          if (body.includes(marker)) {
            log(`[!] Reflected XSS — parameter: ${param}`, '#ff9900');
            finding({
              id: vulnId++, type: 'xss', severity: 'High',
              url: parsed.pathname || '/', param,
              detail: `Reflected XSS detected: the value of parameter "${param}" appears unescaped in the response. Payload: ${payload}`,
              remediation: 'HTML-encode all user-supplied input before rendering in HTML. Apply a strong Content-Security-Policy. Use framework templating with auto-escaping (React, Angular, Vue, Jinja2).',
            });
            xssFound = true;
            break outer;
          }
        }
      }

      if (!xssFound) log('[✓] No reflected XSS detected in tested parameters', '#44ff99');
      log('[*] XSS check complete', '#aaa');
    }

    // ─── 5. SQL injection — error-based detection ──────────────────────────────

    if (scanTypes.includes('sqli')) {
      progress(72, 'Testing for SQL injection...');
      log('[*] Testing for SQL injection error disclosure...', '#aaa');

      const sqliPayloads = ["'", "''", `1'`, `1 OR 1=1--`, `' OR 'a'='a`];
      const errorPatterns = [
        /sql\s+syntax/i,
        /mysql_fetch/i,
        /ORA-\d{5}/,
        /sqlite_/i,
        /pg_query/i,
        /valid MySQL/i,
        /Microsoft SQL\s/i,
        /SQLSTATE\[/i,
        /Unclosed\s+quotation\s+mark/i,
        /quoted\s+string\s+not\s+properly\s+terminated/i,
        /Warning.*mysql/i,
        /MariaDB/i,
        /PSQLException/i,
        /SQLiteException/i,
        /db_query\s+error/i,
      ];

      const testParams = ['id', 'user', 'username', 'q', 'search', 'page', 'cat', 'item', 'pid', 'uid'];
      let sqliFound = false;

      outer: for (const param of testParams) {
        for (const payload of sqliPayloads) {
          const testUrl = `${targetUrl}${targetUrl.includes('?') ? '&' : '?'}${param}=${encodeURIComponent(payload)}`;
          const r = await safeFetch(testUrl);
          if (!r) continue;

          const body    = await safeText(r, 200_000);
          const matched = errorPatterns.find(re => re.test(body));

          if (matched) {
            log(`[!] SQL error detected — parameter: ${param}`, '#ff4444');
            finding({
              id: vulnId++, type: 'sqli', severity: 'Critical',
              url: parsed.pathname || '/', param,
              detail: `SQL error message exposed in response for parameter "${param}" (payload: ${payload}). Error-based SQL injection may allow attackers to extract or manipulate database data.`,
              remediation: 'Use parameterised queries / prepared statements exclusively. Never concatenate user input into SQL strings. Suppress verbose DB error messages in production.',
            });
            sqliFound = true;
            break outer;
          }
        }
      }

      if (!sqliFound) log('[✓] No SQL error disclosure detected', '#44ff99');
      log('[*] SQL injection check complete', '#aaa');
    }

    // ─── 6. CSRF — token presence on POST forms ────────────────────────────────

    if (scanTypes.includes('csrf')) {
      progress(85, 'Checking CSRF protections...');
      log('[*] Inspecting forms for CSRF token presence...', '#aaa');

      const $doc = cheerio.load(mainBody);
      let csrfIssues = 0;

      $doc('form').each((_, form) => {
        const $form  = $doc(form);
        const method = ($form.attr('method') || 'get').toLowerCase();
        if (method !== 'post') return;

        const hasToken = $form.find([
          'input[name*="csrf"]',
          'input[name*="token"]',
          'input[name*="_token"]',
          'input[name*="nonce"]',
          'input[name*="authenticity"]',
          'input[name*="__RequestVerificationToken"]',
        ].join(',')).length > 0;

        if (!hasToken) {
          const action = $form.attr('action') || parsed.pathname || '/';
          log(`[!] POST form without CSRF token: ${action}`, '#cc44ff');
          finding({
            id: vulnId++, type: 'csrf', severity: 'Medium',
            url: action, param: 'form',
            detail: `POST form at "${action}" has no detectable CSRF token. An attacker can trick an authenticated user into submitting this form from a malicious page.`,
            remediation: 'Add a unique per-session CSRF token to every state-changing form as a hidden input field, and verify it server-side on every POST/PUT/DELETE request.',
          });
          csrfIssues++;
        }
      });

      if (!csrfIssues) log('[✓] No unprotected POST forms found on this page', '#44ff99');
      log('[*] CSRF check complete', '#aaa');
    }

    // ─── 7. robots.txt — info disclosure ──────────────────────────────────────

    progress(93, 'Checking robots.txt...');
    log('[*] Checking robots.txt...', '#aaa');

    const robotsRes = await safeFetch(`${baseUrl}/robots.txt`);
    if (robotsRes && robotsRes.status === 200) {
      const robotsBody = await safeText(robotsRes);
      const disallowed = (robotsBody.match(/^Disallow:\s*(.+)$/gim) || []).map(l => l.replace(/^Disallow:\s*/i, '').trim());
      const sensitive  = disallowed.filter(p => /admin|backup|config|secret|private|internal|api|db|dump|passwd|password|shadow/i.test(p));

      if (sensitive.length > 0) {
        log(`[!] robots.txt exposes ${sensitive.length} sensitive path(s)`, '#ffbb00');
        finding({
          id: vulnId++, type: 'misconfig', severity: 'Low',
          url: '/robots.txt', param: 'Disallow',
          detail: `robots.txt lists potentially sensitive paths (${sensitive.slice(0, 5).join(', ')}). This acts as an attacker's roadmap to interesting endpoints.`,
          remediation: 'Do not list sensitive paths in robots.txt. Protect resources through proper authentication, not obscurity.',
        });
      } else {
        log('[✓] robots.txt — no sensitive path disclosure', '#44ff99');
      }
    }

    // ─── Done ──────────────────────────────────────────────────────────────────

    progress(100, 'Complete');
    log('[✓] Hunt complete!', '#ff6b9d');
    send({ type: 'complete' });
    res.end();

  } catch (err) {
    send({ type: 'error', message: err.message });
    res.end();
  }
});

// ─── Save scan results to MongoDB ─────────────────────────────────────────────

app.post('/api/save-scan', async (req, res) => {
  try {
    const { targetUrl, results, timestamp } = req.body;

    if (!targetUrl || !results || !Array.isArray(results)) {
      return res.status(400).json({ error: 'Missing targetUrl or results array' });
    }

    const db = await getDatabase();
    const scansCollection = db.collection('scans');

    const scanRecord = {
      targetUrl,
      results,
      timestamp: timestamp || new Date(),
      summaryCount: {
        total: results.length,
        critical: results.filter(r => r.severity === 'Critical').length,
        high: results.filter(r => r.severity === 'High').length,
        medium: results.filter(r => r.severity === 'Medium').length,
        low: results.filter(r => r.severity === 'Low').length,
      },
    };

    const result = await scansCollection.insertOne(scanRecord);

    res.json({
      success: true,
      message: 'Scan results saved',
      scanId: result.insertedId,
    });
  } catch (err) {
    console.error('Error saving scan:', err);
    res.status(500).json({ error: 'Failed to save scan results' });
  }
});

// ─── Retrieve scan results ───────────────────────────────────────────────────

app.get('/api/scans', async (req, res) => {
  try {
    const db = await getDatabase();
    const scansCollection = db.collection('scans');

    const scans = await scansCollection.find({}).sort({ timestamp: -1 }).limit(50).toArray();

    res.json({
      success: true,
      count: scans.length,
      scans,
    });
  } catch (err) {
    console.error('Error retrieving scans:', err);
    res.status(500).json({ error: 'Failed to retrieve scans' });
  }
});

app.listen(PORT, async () => {
  console.log(`\n�  VulnProbe is running → http://localhost:${PORT}\n`);
  console.log('  ⚠️  Only scan sites you own or have explicit permission to test.\n');

  try {
    await getDatabase();
    console.log('📊 Database connection ready\n');
  } catch (err) {
    console.error('⚠️  Database connection failed. Continuing without persistence.\n');
  }
});
