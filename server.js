const express = require('express');
const cookieSession = require('cookie-session');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { S3Client, ListObjectsV2Command, GetObjectCommand, PutObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme';
const WEBHOOK_URL = process.env.WEBHOOK_URL || '';

app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieSession({
  name: 'session',
  keys: [process.env.SESSION_SECRET || 'agent-gate-secret'],
  maxAge: 7 * 24 * 60 * 60 * 1000,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax'
}));

let agents = new Map();
let logs = [];
let users = new Map();
let audit = [];
let cookieLogs = [];
const inflight = new Map();
const seenNonces = new Set();
const rateWarnSent = new Set();
const mcpSessions = new Map();

function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      agents = new Map(data.agents || []);
      logs = data.logs || [];
      users = new Map(data.users || []);
      audit = data.audit || [];
      cookieLogs = data.cookieLogs || [];
    }
  } catch (e) { console.error('Load failed', e); }
}
function saveData() {
  const data = { agents: Array.from(agents.entries()), logs: logs.slice(-500), users: Array.from(users.entries()), audit: audit.slice(-200), cookieLogs: cookieLogs.slice(-500) };
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}
loadData();

if (users.size === 0) {
  const adminId = uuidv4();
  users.set(adminId, { id: adminId, username: 'admin', password: ADMIN_PASSWORD, role: 'admin' });
  saveData();
}

function logAudit(user, action, detail) {
  audit.push({ timestamp: new Date().toISOString(), user: user || 'system', action, detail });
  saveData();
}

async function notify(event, payload) {
  if (!WEBHOOK_URL) return;
  try {
    await fetch(WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event, ...payload, timestamp: new Date().toISOString() })
    });
  } catch (e) { console.error('Webhook failed', e.message); }
}

function checkRateLimit(agent) {
  const limit = agent.hourlyLimit || 1000;
  const now = Date.now();
  agent.callTimestamps = (agent.callTimestamps || []).filter(t => now - t < 3600000);
  const count = agent.callTimestamps.length;
  if (count >= limit * 0.8 && !rateWarnSent.has(agent.id)) {
    rateWarnSent.add(agent.id);
    notify('rate_warning', { agentId: agent.id, count, limit });
    setTimeout(() => rateWarnSent.delete(agent.id), 3600000);
  }
  if (count >= limit) return false;
  agent.callTimestamps.push(now);
  return true;
}

function isAllowed(permissions, action, resource) {
  if (!permissions || permissions.length === 0) return true;
  const check = resource ? `${action}:${resource}` : action;
  return permissions.some(p => {
    if (p === '*' || p === action || p === check) return true;
    if (p.endsWith('*')) {
      const prefix = p.slice(0, -1);
      return action.startsWith(prefix) || check.startsWith(prefix);
    }
    return false;
  });
}

function getCredentials(agent, system, action) {
  const override = agent.credentials && agent.credentials[system];
  if (override) {
    if (typeof override === 'object' && (override.read || override.write)) {
      const isWrite = ['put', 'write', 'delete', 'create_issue', 'post'].includes(action);
      return isWrite ? (override.write || override.read) : (override.read || override);
    }
    return override;
  }
  if (system === 's3') return {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: (process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || 'us-east-1').trim()
  };
  if (system === 'github') return process.env.GITHUB_TOKEN;
  if (system === 'slack') return process.env.SLACK_BOT_TOKEN;
  return null;
}

function checkIpAllowlist(agent, ip) {
  if (!agent.ipAllowlist || agent.ipAllowlist.length === 0) return true;
  return agent.ipAllowlist.includes(ip);
}

function checkKeyExpiry(agent) {
  if (!agent.keyExpiresAt) return true;
  return new Date(agent.keyExpiresAt) > new Date();
}

function checkReplay(timestamp, nonce) {
  if (!timestamp) return true;
  const ts = parseInt(timestamp, 10);
  if (isNaN(ts) || Math.abs(Date.now() - ts) > 5 * 60 * 1000) return false;
  if (nonce) {
    if (seenNonces.has(nonce)) return false;
    seenNonces.add(nonce);
    setTimeout(() => seenNonces.delete(nonce), 10 * 60 * 1000);
  }
  return true;
}

function errorResponse(id, code, message, retryable = false) {
  return { jsonrpc: '2.0', id, error: { code, message, data: { retryable } } };
}

const systems = new Map();

systems.set('http', {
  handler: async (action, resource, extra, signal) => {
    if (!resource || !resource.startsWith('http')) throw new Error('resource must be a full URL');
    const method = (action === 'write' || action === 'delete' || action === 'POST' || action === 'PUT') ? (action.length <= 6 ? action.toUpperCase() : 'GET') : 'GET';
    const res = await fetch(resource, { method: method === 'DELETE' ? 'DELETE' : method === 'POST' || method === 'PUT' || method === 'WRITE' ? 'POST' : 'GET', signal });
    const text = await res.text();
    return { status: res.status, ok: res.ok, body: text.slice(0, 500) };
  }
});

if (process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY) {
  systems.set('s3', {
    handler: async (action, resource, extra, signal, creds) => {
      const c = creds || getCredentials({}, 's3');
      const s3 = new S3Client({ region: c.region, credentials: { accessKeyId: c.accessKeyId, secretAccessKey: c.secretAccessKey } });
      const [bucket, ...keyParts] = (resource || '').split('/');
      const key = keyParts.join('/');
      if (!bucket) throw new Error('resource must be bucket or bucket/key');
      if (action === 'list' || (action === 'read' && !key)) {
        const out = await s3.send(new ListObjectsV2Command({ Bucket: bucket, MaxKeys: 50 }));
        return { objects: (out.Contents || []).map(o => ({ key: o.Key, size: o.Size })) };
      }
      if (action === 'get' || (action === 'read' && key)) {
        const out = await s3.send(new GetObjectCommand({ Bucket: bucket, Key: key }));
        const body = await out.Body.transformToString();
        return { key, body: body.slice(0, 2000) };
      }
      if (action === 'put' || action === 'write') {
        await s3.send(new PutObjectCommand({ Bucket: bucket, Key: key, Body: extra?.body || '' }));
        return { uploaded: key };
      }
      if (action === 'delete') {
        await s3.send(new DeleteObjectCommand({ Bucket: bucket, Key: key }));
        return { deleted: key };
      }
      throw new Error('unsupported s3 action');
    }
  });
}

if (process.env.GITHUB_TOKEN) {
  systems.set('github', {
    handler: async (action, resource, extra, signal, creds) => {
      const token = creds || process.env.GITHUB_TOKEN;
      const [owner, repo, ...rest] = (resource || '').split('/');
      if (!owner || !repo) throw new Error('resource must be owner/repo[/...]');
      const base = `https://api.github.com/repos/${owner}/${repo}`;
      const headers = { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'User-Agent': 'agent-gate' };
      if (action === 'create_issue') {
        const res = await fetch(`${base}/issues`, { method: 'POST', headers: { ...headers, 'Content-Type': 'application/json' }, body: JSON.stringify({ title: extra.title, body: extra.body || '' }), signal });
        const data = await res.json();
        if (!res.ok) throw new Error(JSON.stringify(data).slice(0, 300));
        return { number: data.number, url: data.html_url };
      }
      if (action === 'list_prs') {
        const res = await fetch(`${base}/pulls?state=open`, { headers, signal });
        const data = await res.json();
        if (!res.ok) throw new Error(JSON.stringify(data).slice(0, 300));
        return { prs: data.slice(0, 20).map(p => ({ number: p.number, title: p.title })) };
      }
      let url = base;
      if (rest.length) url += '/' + rest.join('/');
      const res = await fetch(url, { headers, signal });
      const body = await res.text();
      if (!res.ok) throw new Error(`GitHub ${res.status}: ${body.slice(0, 300)}`);
      return { status: res.status, body: body.slice(0, 2000) };
    }
  });
}

if (process.env.SLACK_BOT_TOKEN) {
  systems.set('slack', {
    handler: async (action, resource, extra, signal, creds) => {
      const token = creds || process.env.SLACK_BOT_TOKEN;
      if (action === 'post') {
        const res = await fetch('https://slack.com/api/chat.postMessage', {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ channel: resource, text: extra.text }),
          signal
        });
        const data = await res.json();
        if (!data.ok) throw new Error(data.error);
        return { ts: data.ts, channel: data.channel };
      }
      if (action === 'list_channels') {
        const res = await fetch('https://slack.com/api/conversations.list', { headers: { Authorization: `Bearer ${token}` }, signal });
        const data = await res.json();
        if (!data.ok) throw new Error(data.error);
        return { channels: (data.channels || []).slice(0, 30).map(c => ({ id: c.id, name: c.name })) };
      }
      throw new Error('unsupported slack action');
    }
  });
}

async function executeGated(agent, system, action, resource, extra, req) {
  const ip = req.ip || req.headers['x-forwarded-for'] || '';
  if (!checkIpAllowlist(agent, ip)) {
    await notify('ip_blocked', { agentId: agent.id, ip });
    throw new Error('IP not allowed');
  }
  if (!checkKeyExpiry(agent)) {
    await notify('key_expired', { agentId: agent.id });
    throw new Error('Key expired');
  }
  const ts = req.headers['x-timestamp'];
  const nonce = req.headers['x-nonce'];
  if (!checkReplay(ts, nonce)) {
    await notify('replay_blocked', { agentId: agent.id });
    throw new Error('Invalid or replayed timestamp');
  }
  if (!checkRateLimit(agent)) {
    await notify('rate_limited', { agentId: agent.id, action, resource });
    throw new Error('hourly limit exceeded');
  }
  const controller = new AbortController();
  if (!inflight.has(agent.id)) inflight.set(agent.id, new Set());
  inflight.get(agent.id).add(controller);

  try {
    const creds = getCredentials(agent, system, action);
    const backend = systems.get(system);
    if (!backend) throw new Error('backend not configured');
    const result = await backend.handler(action, resource, extra, controller.signal, creds);
    return result;
  } finally {
    inflight.get(agent.id)?.delete(controller);
  }
}

app.post('/mcp', async (req, res) => {
  const body = req.body;
  const id = body.id;
  const method = body.method;
  const sessionId = req.headers['mcp-session-id'] || body.params?.sessionId;
  const auth = req.headers.authorization || '';
  let key = auth.startsWith('Bearer ') ? auth.slice(7) : (body.params && body.params.key);
  if (!key && sessionId) key = mcpSessions.get(sessionId);

  if (method === 'initialize') {
    const newSession = uuidv4();
    if (key) mcpSessions.set(newSession, key);
    return res.json({
      jsonrpc: '2.0', id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: { listChanged: false } },
        serverInfo: { name: 'agent-gate', version: '1.0.0' },
        sessionId: newSession
      }
    });
  }

  if (method === 'tools/list') {
    const tools = [
      { name: 's3_list', description: 'List objects in an S3 bucket', inputSchema: { type: 'object', properties: { bucket: { type: 'string' } }, required: ['bucket'] } },
      { name: 's3_get', description: 'Get an object from S3', inputSchema: { type: 'object', properties: { bucket: { type: 'string' }, key: { type: 'string' } }, required: ['bucket', 'key'] } },
      { name: 's3_put', description: 'Upload an object to S3', inputSchema: { type: 'object', properties: { bucket: { type: 'string' }, key: { type: 'string' }, body: { type: 'string' } }, required: ['bucket', 'key', 'body'] } },
      { name: 's3_delete', description: 'Delete an object from S3', inputSchema: { type: 'object', properties: { bucket: { type: 'string' }, key: { type: 'string' } }, required: ['bucket', 'key'] } },
      { name: 'github_get', description: 'GET a GitHub path', inputSchema: { type: 'object', properties: { path: { type: 'string' } }, required: ['path'] } },
      { name: 'github_create_issue', description: 'Create a GitHub issue', inputSchema: { type: 'object', properties: { repo: { type: 'string' }, title: { type: 'string' }, body: { type: 'string' } }, required: ['repo', 'title'] } },
      { name: 'github_list_prs', description: 'List open PRs', inputSchema: { type: 'object', properties: { repo: { type: 'string' } }, required: ['repo'] } },
      { name: 'slack_post', description: 'Post a message to Slack', inputSchema: { type: 'object', properties: { channel: { type: 'string' }, text: { type: 'string' } }, required: ['channel', 'text'] } },
      { name: 'slack_list_channels', description: 'List Slack channels', inputSchema: { type: 'object', properties: {} } },
      { name: 'http_get', description: 'HTTP GET a URL', inputSchema: { type: 'object', properties: { url: { type: 'string' } }, required: ['url'] } }
    ];
    return res.json({ jsonrpc: '2.0', id, result: { tools } });
  }

  if (method === 'tools/call') {
    if (!key) return res.json(errorResponse(id, -32000, 'Agent key required (Authorization header or session)', false));
    const agent = Array.from(agents.values()).find(a => a.key === key);
    if (!agent || !agent.active) return res.json(errorResponse(id, -32001, 'Invalid or killed key', false));

    const toolName = body.params && body.params.name;
    const args = (body.params && body.params.arguments) || {};
    let action, resource, system, extra = {};
    if (toolName === 's3_list') { system = 's3'; action = 'list'; resource = args.bucket; }
    else if (toolName === 's3_get') { system = 's3'; action = 'get'; resource = `${args.bucket}/${args.key}`; }
    else if (toolName === 's3_put') { system = 's3'; action = 'put'; resource = `${args.bucket}/${args.key}`; extra.body = args.body; }
    else if (toolName === 's3_delete') { system = 's3'; action = 'delete'; resource = `${args.bucket}/${args.key}`; }
    else if (toolName === 'github_get') { system = 'github'; action = 'read'; resource = args.path; }
    else if (toolName === 'github_create_issue') { system = 'github'; action = 'create_issue'; resource = args.repo; extra.title = args.title; extra.body = args.body; }
    else if (toolName === 'github_list_prs') { system = 'github'; action = 'list_prs'; resource = args.repo; }
    else if (toolName === 'slack_post') { system = 'slack'; action = 'post'; resource = args.channel; extra.text = args.text; }
    else if (toolName === 'slack_list_channels') { system = 'slack'; action = 'list_channels'; resource = 'channels'; }
    else if (toolName === 'http_get') { system = 'http'; action = 'read'; resource = args.url; }
    else return res.json(errorResponse(id, -32601, 'Unknown tool', false));

    if (!isAllowed(agent.permissions, action, resource)) {
      logs.push({ timestamp: new Date().toISOString(), agentId: agent.id, system, action, resource, result: 'refused' });
      saveData();
      await notify('refused', { agentId: agent.id, action, resource });
      return res.json({ jsonrpc: '2.0', id, result: { content: [{ type: 'text', text: 'Action not permitted' }], isError: true, structuredContent: { error: 'permission_denied', retryable: false } } });
    }

    try {
      const result = await executeGated(agent, system, action, resource, extra, req);
      logs.push({ timestamp: new Date().toISOString(), agentId: agent.id, system, action, resource, result: 'allowed', detail: result });
      saveData();
      return res.json({
        jsonrpc: '2.0', id,
        result: {
          content: [{ type: 'text', text: JSON.stringify(result) }],
          structuredContent: result,
          isError: false
        }
      });
    } catch (err) {
      logs.push({ timestamp: new Date().toISOString(), agentId: agent.id, system, action, resource, result: 'error', detail: err.message });
      saveData();
      const retryable = err.message.includes('limit') || err.message.includes('timeout');
      return res.json({
        jsonrpc: '2.0', id,
        result: {
          content: [{ type: 'text', text: err.message }],
          structuredContent: { error: err.message, retryable },
          isError: true
        }
      });
    }
  }

  res.json(errorResponse(id, -32601, 'Method not found', false));
});

app.post('/api/gate', async (req, res) => {
  const { key, action, resource, system } = req.body;
  if (!key) return res.status(400).json({ error: 'key required', code: 'missing_key', retryable: false });
  const agent = Array.from(agents.values()).find(a => a.key === key);
  const entry = { timestamp: new Date().toISOString(), agentId: agent?.id || null, system: system || agent?.system || 'http', action, resource, result: 'refused' };
  if (!agent || !agent.active) { logs.push(entry); saveData(); return res.status(403).json({ error: 'invalid or killed key', code: 'invalid_key', retryable: false }); }
  if (!isAllowed(agent.permissions, action, resource)) { logs.push(entry); saveData(); await notify('refused', { agentId: agent.id, action, resource }); return res.status(403).json({ error: 'action not permitted', code: 'permission_denied', retryable: false }); }
  try {
    const result = await executeGated(agent, entry.system, action, resource, {}, req);
    entry.result = 'allowed'; entry.detail = result;
    logs.push(entry); saveData();
    return res.json({ status: 'allowed', executed: true, result });
  } catch (err) {
    entry.result = 'error'; entry.detail = err.message;
    logs.push(entry); saveData();
    const retryable = err.message.includes('limit') || err.message.includes('timeout');
    return res.status(502).json({ error: 'action failed', detail: err.message, code: 'execution_error', retryable });
  }
});

app.post('/api/cookie', (req, res) => {
  const ip = req.ip || req.headers['x-forwarded-for'] || 'unknown';
  cookieLogs.push({ timestamp: new Date().toISOString(), choice: req.body.choice, ip });
  saveData();
  res.json({ ok: true });
});

app.post('/api/contact', (req, res) => {
  const { name, email, company, message, plan } = req.body;
  if (!name || !email || !message) return res.status(400).json({ error: 'name, email, message required' });
  const entry = { timestamp: new Date().toISOString(), name, email, company: company || '', message, plan: plan || 'unknown' };
  if (!global.contacts) global.contacts = [];
  global.contacts.push(entry);
  console.log('CONTACT:', JSON.stringify(entry));
  res.json({ ok: true });
});

function requireAuth(req, res, next) {
  if (req.session && req.session.authed) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'login required' });
  res.redirect('/login');
}

app.get('/', (req, res) => {
  if (req.session && req.session.authed) return res.redirect('/app');
  res.sendFile(path.join(__dirname, 'public', 'landing.html'));
});

app.get('/terms', (req, res) => res.sendFile(path.join(__dirname, 'public', 'terms.html')));
app.get('/privacy', (req, res) => res.sendFile(path.join(__dirname, 'public', 'privacy.html')));
app.get('/pricing', (req, res) => res.sendFile(path.join(__dirname, 'public', 'pricing.html')));

app.get('/login', (req, res) => {
  res.send(`<!DOCTYPE html><html><head><title>Login</title><style>body{background:#000;color:#e0e0e0;font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}form{background:#111;padding:2.5rem;border-radius:8px;border:1px solid #555;min-width:280px}h2{margin:0 0 1.5rem;font-weight:600}input,button{display:block;margin:0.6rem 0;padding:0.7rem;width:100%;background:#000;color:#e0e0e0;border:1px solid #555;border-radius:4px;font-size:1rem}button{background:#fff;color:#000;border:none;font-weight:500;cursor:pointer}button:hover{opacity:0.9}</style></head><body><form method="POST" action="/login"><h2>Agent Gate</h2><input name="username" placeholder="Username" required><input name="password" type="password" placeholder="Password" required><button>Login</button></form></body></html>`);
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = Array.from(users.values()).find(u => u.username === username && u.password === password);
  if (user) {
    req.session.authed = true;
    req.session.user = user.username;
    logAudit(user.username, 'login', {});
    return res.redirect('/app');
  }
  res.redirect('/login');
});

app.get('/logout', (req, res) => { req.session = null; res.redirect('/'); });

app.get('/app', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'app.html'));
});

app.use(requireAuth);
app.use(express.static('public'));

app.get('/health', async (req, res) => {
  const checks = { ok: true };
  if (process.env.AWS_ACCESS_KEY_ID) {
    try {
      const s3 = new S3Client({ region: (process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION || 'us-east-1').trim(), credentials: { accessKeyId: process.env.AWS_ACCESS_KEY_ID, secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY } });
      await s3.send(new ListObjectsV2Command({ Bucket: 'nonexistent-test-bucket-xyz', MaxKeys: 1 }));
      checks.aws = 'ok';
    } catch (e) {
      checks.aws = e.name === 'NoSuchBucket' || e.Code === 'NoSuchBucket' ? 'ok' : 'error';
      if (checks.aws === 'error') checks.ok = false;
    }
  }
  if (process.env.GITHUB_TOKEN) {
    try {
      const r = await fetch('https://api.github.com/user', { headers: { Authorization: `Bearer ${process.env.GITHUB_TOKEN}`, 'User-Agent': 'agent-gate' } });
      checks.github = r.ok ? 'ok' : 'error';
      if (!r.ok) checks.ok = false;
    } catch { checks.github = 'error'; checks.ok = false; }
  }
  if (process.env.SLACK_BOT_TOKEN) {
    try {
      const r = await fetch('https://slack.com/api/auth.test', { headers: { Authorization: `Bearer ${process.env.SLACK_BOT_TOKEN}` } });
      const d = await r.json();
      checks.slack = d.ok ? 'ok' : 'error';
      if (!d.ok) checks.ok = false;
    } catch { checks.slack = 'error'; checks.ok = false; }
  }
  res.status(checks.ok ? 200 : 503).json(checks);
});

app.post('/api/users', (req, res) => {
  if (req.session.user !== 'admin') return res.status(403).json({ error: 'admin only' });
  const { username, password, role } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  const id = uuidv4();
  users.set(id, { id, username, password, role: role || 'user' });
  saveData();
  logAudit(req.session.user, 'create_user', { username });
  res.json({ id, username });
});

app.get('/api/users', (req, res) => {
  if (req.session.user !== 'admin') return res.status(403).json({ error: 'admin only' });
  const list = Array.from(users.values()).map(({ password, ...rest }) => rest);
  res.json(list);
});

app.post('/api/agents', (req, res) => {
  const { name, owner, permissions, system, hourlyLimit, credentials, ipAllowlist, keyExpiresInDays } = req.body;
  if (!name || !owner) return res.status(400).json({ error: 'name and owner required' });
  const id = uuidv4();
  const key = uuidv4();
  const perms = Array.isArray(permissions) ? permissions : (permissions || '').split(',').map(s => s.trim()).filter(Boolean);
  const agent = {
    id, name, owner, system: system || 'http', permissions: perms, key, active: true,
    createdAt: new Date().toISOString(),
    hourlyLimit: hourlyLimit || 1000,
    credentials: credentials || null,
    ipAllowlist: Array.isArray(ipAllowlist) ? ipAllowlist : null,
    keyExpiresAt: keyExpiresInDays ? new Date(Date.now() + keyExpiresInDays * 86400000).toISOString() : null,
    callTimestamps: []
  };
  agents.set(id, agent);
  saveData();
  logAudit(req.session.user, 'create_agent', { agentId: id, name });
  res.json({ id, key, message: 'Agent created. Store the key securely; it will not be shown again.' });
});

app.get('/api/agents', (req, res) => {
  const list = Array.from(agents.values()).map(({ key, credentials, callTimestamps, ...rest }) => rest);
  res.json(list);
});

app.patch('/api/agents/:id', (req, res) => {
  const agent = agents.get(req.params.id);
  if (!agent) return res.status(404).json({ error: 'not found' });
  const { permissions, hourlyLimit, ipAllowlist, name, owner } = req.body;
  if (permissions) agent.permissions = Array.isArray(permissions) ? permissions : permissions.split(',').map(s => s.trim()).filter(Boolean);
  if (hourlyLimit !== undefined) agent.hourlyLimit = hourlyLimit;
  if (ipAllowlist !== undefined) agent.ipAllowlist = Array.isArray(ipAllowlist) ? ipAllowlist : null;
  if (name) agent.name = name;
  if (owner) agent.owner = owner;
  saveData();
  logAudit(req.session.user, 'update_agent', { agentId: agent.id });
  res.json({ message: 'Agent updated' });
});

app.post('/api/agents/:id/kill', async (req, res) => {
  const agent = agents.get(req.params.id);
  if (!agent) return res.status(404).json({ error: 'not found' });
  agent.active = false;
  const controllers = inflight.get(agent.id);
  if (controllers) {
    for (const c of controllers) c.abort();
    inflight.delete(agent.id);
  }
  saveData();
  logAudit(req.session.user, 'kill_agent', { agentId: agent.id, name: agent.name });
  await notify('killed', { agentId: agent.id, name: agent.name });
  res.json({ message: 'Agent killed and in-flight requests aborted' });
});

app.post('/api/agents/:id/rotate', (req, res) => {
  const agent = agents.get(req.params.id);
  if (!agent) return res.status(404).json({ error: 'not found' });
  agent.key = uuidv4();
  if (req.body.keyExpiresInDays) {
    agent.keyExpiresAt = new Date(Date.now() + req.body.keyExpiresInDays * 86400000).toISOString();
  }
  saveData();
  logAudit(req.session.user, 'rotate_key', { agentId: agent.id });
  res.json({ key: agent.key, message: 'Key rotated. Store the new key.' });
});

app.get('/api/backup', (req, res) => {
  const data = { agents: Array.from(agents.entries()), logs, users: Array.from(users.entries()), audit, cookieLogs };
  res.setHeader('Content-Disposition', 'attachment; filename="agent-gate-backup.json"');
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify(data, null, 2));
});

app.post('/api/restore', (req, res) => {
  if (req.session.user !== 'admin') return res.status(403).json({ error: 'admin only' });
  const { agents: a, logs: l, users: u, audit: au, cookieLogs: cl } = req.body;
  if (!a || !Array.isArray(a)) return res.status(400).json({ error: 'invalid backup' });
  agents = new Map(a);
  logs = l || [];
  if (u) users = new Map(u);
  if (au) audit = au;
  if (cl) cookieLogs = cl;
  saveData();
  logAudit(req.session.user, 'restore', {});
  res.json({ message: 'Restored', agents: agents.size, logs: logs.length });
});

app.get('/api/logs', (req, res) => res.json(logs.slice(-100)));

app.get('/api/logs/export', (req, res) => {
  const filename = `logs-${new Date().toISOString().slice(0, 10)}.json`;
  res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify(logs, null, 2));
});

app.get('/api/stats', (req, res) => {
  const today = new Date().toISOString().slice(0, 10);
  const todayLogs = logs.filter(l => l.timestamp && l.timestamp.startsWith(today));
  const allowed = todayLogs.filter(l => l.result === 'allowed').length;
  const refused = todayLogs.filter(l => l.result === 'refused').length;
  const errors = todayLogs.filter(l => l.result === 'error').length;
  const byAgent = {};
  for (const l of todayLogs) {
    const id = l.agentId || 'unknown';
    byAgent[id] = (byAgent[id] || 0) + 1;
  }
  const topAgents = Object.entries(byAgent).sort((a, b) => b[1] - a[1]).slice(0, 5);
  res.json({ date: today, allowed, refused, errors, total: todayLogs.length, topAgents });
});

app.get('/api/audit', (req, res) => {
  if (req.session.user !== 'admin') return res.status(403).json({ error: 'admin only' });
  res.json(audit.slice(-100));
});

app.get('/api/cookies', (req, res) => {
  if (req.session.user !== 'admin') return res.status(403).json({ error: 'admin only' });
  res.json(cookieLogs.slice(-100));
});

app.listen(PORT, () => console.log(`Agent Gate listening on port ${PORT}`));
