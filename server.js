const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Ubaidullah@2026';
const root = __dirname;
const dataDir = path.join(root, 'data');
const messagesFile = path.join(dataDir, 'messages.json');
fs.mkdirSync(dataDir, { recursive: true });
if (!fs.existsSync(messagesFile)) fs.writeFileSync(messagesFile, '[]');

const sessions = new Map();
const loginAttempts = new Map();
const mime = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

function send(res, status, body, type = 'application/json; charset=utf-8', extra = {}) {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', ...extra });
  res.end(body);
}
function json(res, status, data, type = 'application/json; charset=utf-8', extra = {}) { send(res, status, JSON.stringify(data), type, extra); }
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > 1e6) { req.destroy(); reject(new Error('Payload too large')); }
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}
function parseCookies(req) {
  const out = {};
  (req.headers.cookie || '').split(';').forEach(pair => {
    const i = pair.indexOf('=');
    if (i > -1) out[pair.slice(0, i).trim()] = decodeURIComponent(pair.slice(i + 1).trim());
  });
  return out;
}
function getSession(req) {
  const token = parseCookies(req).ubaidullah_admin;
  if (!token) return null;
  const session = sessions.get(token);
  if (!session) return null;
  if (Date.now() > session.expiresAt) { sessions.delete(token); return null; }
  session.expiresAt = Date.now() + 8 * 60 * 60 * 1000;
  return { token, ...session };
}
function requireAdmin(req, res) {
  const session = getSession(req);
  if (!session) { json(res, 401, { error: 'Unauthorized' }); return null; }
  return session;
}
function safeEqual(a, b) {
  const aa = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}
function readMessages() {
  try { return JSON.parse(fs.readFileSync(messagesFile, 'utf8') || '[]'); }
  catch { return []; }
}
function writeMessages(items) { fs.writeFileSync(messagesFile, JSON.stringify(items, null, 2)); }

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = decodeURIComponent(url.pathname);

  // Public contact form
  if (req.method === 'POST' && pathname === '/api/contact') {
    try {
      const item = JSON.parse(await readBody(req) || '{}');
      if (!item.name || !item.email || !item.message) return json(res, 400, { error: 'Name, email and message are required.' });
      const all = readMessages();
      all.push({
        id: crypto.randomUUID(),
        name: String(item.name).slice(0, 120),
        email: String(item.email).slice(0, 200),
        project: String(item.project || '').slice(0, 100),
        message: String(item.message).slice(0, 5000),
        read: false,
        createdAt: new Date().toISOString()
      });
      writeMessages(all);
      return json(res, 201, { ok: true });
    } catch { return json(res, 400, { error: 'Invalid request.' }); }
  }

  // Admin login
  if (req.method === 'POST' && pathname === '/api/admin/login') {
    try {
      const ip = req.socket.remoteAddress || 'unknown';
      const attempt = loginAttempts.get(ip) || { count: 0, reset: Date.now() + 15 * 60 * 1000 };
      if (Date.now() > attempt.reset) { attempt.count = 0; attempt.reset = Date.now() + 15 * 60 * 1000; }
      if (attempt.count >= 8) return json(res, 429, { error: 'Too many login attempts. Try again later.' });
      const body = JSON.parse(await readBody(req) || '{}');
      const ok = safeEqual(body.username || '', ADMIN_USER) && safeEqual(body.password || '', ADMIN_PASSWORD);
      if (!ok) { attempt.count++; loginAttempts.set(ip, attempt); return json(res, 401, { error: 'Invalid username or password.' }); }
      loginAttempts.delete(ip);
      const token = crypto.randomBytes(32).toString('hex');
      sessions.set(token, { user: ADMIN_USER, expiresAt: Date.now() + 8 * 60 * 60 * 1000 });
      return json(res, 200, { ok: true }, 'application/json; charset=utf-8', {
        'Set-Cookie': `ubaidullah_admin=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`
      });
    } catch { return json(res, 400, { error: 'Invalid request.' }); }
  }

  if (req.method === 'POST' && pathname === '/api/admin/logout') {
    const token = parseCookies(req).ubaidullah_admin;
    if (token) sessions.delete(token);
    return json(res, 200, { ok: true }, 'application/json; charset=utf-8', {
      'Set-Cookie': 'ubaidullah_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'
    });
  }

  // Protected message APIs
  if (pathname === '/api/admin/messages') {
    if (!requireAdmin(req, res)) return;
    if (req.method === 'GET') return json(res, 200, { messages: readMessages().sort((a,b) => new Date(b.createdAt) - new Date(a.createdAt)) });
    if (req.method === 'DELETE') {
      try {
        const body = JSON.parse(await readBody(req) || '{}');
        const id = String(body.id || '');
        const all = readMessages();
        const next = all.filter(m => m.id !== id);
        if (next.length === all.length) return json(res, 404, { error: 'Message not found.' });
        writeMessages(next);
        return json(res, 200, { ok: true });
      } catch { return json(res, 400, { error: 'Invalid request.' }); }
    }
  }
  if (req.method === 'POST' && pathname === '/api/admin/messages/read') {
    if (!requireAdmin(req, res)) return;
    try {
      const body = JSON.parse(await readBody(req) || '{}');
      const all = readMessages();
      const item = all.find(m => m.id === String(body.id || ''));
      if (!item) return json(res, 404, { error: 'Message not found.' });
      item.read = true;
      writeMessages(all);
      return json(res, 200, { ok: true });
    } catch { return json(res, 400, { error: 'Invalid request.' }); }
  }
  if (req.method === 'GET' && pathname === '/api/admin/me') {
    const session = getSession(req);
    if (!session) return json(res, 401, { authenticated: false });
    return json(res, 200, { authenticated: true, user: session.user });
  }

  // Never expose the raw messages JSON publicly.
  if (pathname.startsWith('/data/')) return send(res, 403, 'Forbidden', 'text/plain; charset=utf-8');

  let reqPath = pathname;
  if (reqPath === '/') reqPath = '/index.html';
  if (reqPath === '/admin') reqPath = '/admin.html';
  const file = path.normalize(path.join(root, reqPath));
  if (!file.startsWith(root)) return send(res, 403, 'Forbidden', 'text/plain; charset=utf-8');
  fs.readFile(file, (err, data) => {
    if (err) return send(res, 404, 'Not found', 'text/plain; charset=utf-8');
    res.writeHead(200, { 'Content-Type': mime[path.extname(file)] || 'application/octet-stream' });
    res.end(data);
  });
});

server.listen(PORT, () => console.log(`Ubaidullah portfolio running at http://localhost:${PORT}`));
