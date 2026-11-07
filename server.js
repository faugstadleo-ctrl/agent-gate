const express = require('express');
const session = require('express-session');
const { v4: uuidv4 } = require('uuid');
const fs = require('fs');
const path = require('path');
const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = path.join(__dirname, 'data.json');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'changeme';

app.set('trust proxy', 1);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'agent-gate-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production', sameSite: 'lax' }
}));
app.use(express.static('public'));

let agents = new Map();
let logs = [];
function loadData() {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const data = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
      agents = new Map(data.agents || []);
      logs = data.logs || [];
    }
  } catch (e) { console.error('Load failed', e); }
}
function saveData() {
  const data = { agents: Array.from(agents.entries()), logs: logs.slice(-500) };
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2));
}
loadData();

const systems = new Map();

systems.set('http', {
  handler: async (action, resource) => {
    if (!resource || !resource.startsWith('http')) throw new Error('resource must be a full URL');
    const method = (action === 'write' || action === 'delete') ? action.toUpperCase() : 'GET';
    const res = await fetch(resource, { method });
    const text = await res.text();
    return { status: res.status, ok: res.ok, body: text.slice(0, 500) };
  }
});

if (process.env.GITHUB_TOKEN) {
  systems.set('github', {
    credentials: process.env.GITHUB_TOKEN,
    handler: async (action, resource) => {
      const [owner, repo, ...rest] = (resource || '').split('/');
      if (!owner || !repo) throw new Error('resource must be owner/repo[/path]');
      const url = rest.length
        ? `https://api.github.com/repos/${owner}/${repo}/${rest.join('/')}`
        : `https://api.github.com/repos/${owner}/${repo}`;
      const res = await fetch(url, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
          Accept: 'application/vnd.github+json',
          'User-Agent': 'agent-gate'
        }
      });
      const body = await res.text();
      if (!res.ok) throw new Error(`GitHub ${res.status}: ${body.slice(0, 200)}`);
      return { status: res.status, body: body.slice(0, 500) };
    }
  });
}

function requireAuth(req, res, next) {
  if (req.session && req.session.authed) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'login required' });
  res.redirect('/login');
}

app.get('/login', (req, res) => {
  res.send(`<!DOCTYPE html><html><head><title>Login</title><style>body{background:#0f1117;color:#e6e6e6;font-family:system-ui;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}form{background:#1a1d27;padding:2rem;border-radius:8px;border:1px solid #2a2e3a}input,button{display:block;margin:0.5rem 0;padding:0.5rem;width:200px;background:#0f1117;color:#e6e6e6;border:1px solid #2a2e3a}</style></head><body><form method="POST" action="/login"><h2>Agent Gate</h2><input name="password" type="password" placeholder="Password" required><button>Login</button></form></body></html>`);
});

app.post('/login', (req, res) => {
  if (req.body.password === ADMIN_PASSWORD) {
    req.session.authed = true;
    return res.redirect('/');
  }
  res.redirect('/login');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

app.use(requireAuth);

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.post('/api/agents', (req, res) => {
  const { name, owner, permissions, system } = req.body;
  if (!name || !owner) return res.status(400).json({ error: 'name and owner required' });
  const id = uuidv4();
  const key = uuidv4();
  const agent = { id, name, owner, system: system || 'http', permissions: permissions || [], key, active: true, createdAt: new Date().toISOString() };
  agents.set(id, agent);
  saveData();
  res.json({ id, key, message: 'Agent created. Store the key securely; it will not be shown again.' });
});

app.get('/api/agents', (req, res) => {
  const list = Array.from(agents.values()).map(({ key, ...rest }) => rest);
  res.json(list);
});

app.post('/api/agents/:id/kill', (req, res) => {
  const agent = agents.get(req.params.id);
  if (!agent) return res.status(404).json({ error: 'not found' });
  agent.active = false;
  saveData();
  res.json({ message: 'Agent killed' });
});

app.post('/api/gate', async (req, res) => {
  const { key, action, resource, system } = req.body;
  const agent = Array.from(agents.values()).find(a => a.key === key);
  const entry = { timestamp: new Date().toISOString(), agentId: agent?.id || null, system: system || agent?.system || 'http', action, resource, result: 'refused' };

  if (!agent || !agent.active) {
    logs.push(entry); saveData();
    return res.status(403).json({ error: 'invalid or killed key' });
  }
  if (agent.permissions.length && !agent.permissions.includes(action)) {
    logs.push(entry); saveData();
    return res.status(403).json({ error: 'action not permitted' });
  }

  const backend = systems.get(entry.system);
  if (backend && backend.handler) {
    try {
      const result = await backend.handler(action, resource, backend.credentials);
      entry.result = 'allowed';
      entry.detail = result;
      logs.push(entry); saveData();
      return res.json({ status: 'allowed', executed: true, result });
    } catch (err) {
      entry.result = 'error';
      entry.detail = err.message;
      logs.push(entry); saveData();
      return res.status(502).json({ error: 'action failed', detail: err.message });
    }
  }

  entry.result = 'allowed';
  logs.push(entry); saveData();
  res.json({ status: 'allowed', executed: false, message: 'No backend for this system' });
});

app.get('/api/logs', (req, res) => res.json(logs.slice(-100)));

app.listen(PORT, () => console.log(`Agent Gate listening on port ${PORT}`));
