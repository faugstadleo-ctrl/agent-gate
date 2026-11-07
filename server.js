const express = require('express');
const { v4: uuidv4 } = require('uuid');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static('public'));

// In-memory store (replace with DB for persistence)
const agents = new Map();
const logs = [];
const systems = new Map(); // registered backends: name -> { credentials, handler }

// Example: register a system (in real use, load from env/secrets)
// systems.set('example', { credentials: process.env.EXAMPLE_TOKEN, handler: async (action, resource) => { ... } });

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Create agent
app.post('/api/agents', (req, res) => {
  const { name, owner, permissions, system } = req.body;
  if (!name || !owner) {
    return res.status(400).json({ error: 'name and owner required' });
  }
  const id = uuidv4();
  const key = uuidv4();
  const agent = {
    id,
    name,
    owner,
    system: system || 'generic',
    permissions: permissions || [],
    key,
    active: true,
    createdAt: new Date().toISOString()
  };
  agents.set(id, agent);
  res.json({ id, key, message: 'Agent created. Store the key securely; it will not be shown again.' });
});

// List agents (without keys)
app.get('/api/agents', (req, res) => {
  const list = Array.from(agents.values()).map(({ key, ...rest }) => rest);
  res.json(list);
});

// Kill agent
app.post('/api/agents/:id/kill', (req, res) => {
  const agent = agents.get(req.params.id);
  if (!agent) return res.status(404).json({ error: 'not found' });
  agent.active = false;
  res.json({ message: 'Agent killed' });
});

// Gate endpoint — system-agnostic
app.post('/api/gate', async (req, res) => {
  const { key, action, resource, system } = req.body;
  const agent = Array.from(agents.values()).find(a => a.key === key);
  const entry = {
    timestamp: new Date().toISOString(),
    agentId: agent?.id || null,
    system: system || agent?.system || 'generic',
    action,
    resource,
    result: 'refused'
  };

  if (!agent || !agent.active) {
    logs.push(entry);
    return res.status(403).json({ error: 'invalid or killed key' });
  }

  if (agent.permissions.length && !agent.permissions.includes(action)) {
    logs.push(entry);
    return res.status(403).json({ error: 'action not permitted' });
  }

  // Forward to registered system if one exists; otherwise allow for demo
  const backend = systems.get(entry.system);
  if (backend && backend.handler) {
    try {
      const result = await backend.handler(action, resource, backend.credentials);
      entry.result = 'allowed';
      entry.detail = result;
      logs.push(entry);
      return res.json({ status: 'allowed', result });
    } catch (err) {
      entry.result = 'error';
      entry.detail = err.message;
      logs.push(entry);
      return res.status(502).json({ error: 'backend failed', detail: err.message });
    }
  }

  // No backend registered — still enforce the gate
  entry.result = 'allowed';
  logs.push(entry);
  res.json({ status: 'allowed', message: 'Action permitted by gate (no backend registered yet)' });
});

// Get logs
app.get('/api/logs', (req, res) => {
  res.json(logs.slice(-100));
});

app.listen(PORT, () => {
  console.log(`Agent Gate listening on port ${PORT}`);
});
