const express = require('express');
const { v4: uuidv4 } = require('uuid');
const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static('public'));

// In-memory store for demo (replace with DB later)
const agents = new Map();
const logs = [];

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Create agent
app.post('/api/agents', (req, res) => {
  const { name, owner, permissions } = req.body;
  if (!name || !owner) {
    return res.status(400).json({ error: 'name and owner required' });
  }
  const id = uuidv4();
  const key = uuidv4();
  const agent = {
    id,
    name,
    owner,
    permissions: permissions || [],
    key,
    active: true,
    createdAt: new Date().toISOString()
  };
  agents.set(id, agent);
  // Return key only once
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

// Gate endpoint (agent calls this)
app.post('/api/gate', (req, res) => {
  const { key, action, resource } = req.body;
  const agent = Array.from(agents.values()).find(a => a.key === key);
  const entry = {
    timestamp: new Date().toISOString(),
    agentId: agent?.id || null,
    action,
    resource,
    result: 'refused'
  };

  if (!agent || !agent.active) {
    logs.push(entry);
    return res.status(403).json({ error: 'invalid or killed key' });
  }

  if (!agent.permissions.includes(action)) {
    logs.push(entry);
    return res.status(403).json({ error: 'action not permitted' });
  }

  // In real version: use company token to perform the action
  entry.result = 'allowed';
  logs.push(entry);
  res.json({ status: 'allowed', message: 'Action would be forwarded here' });
});

// Get logs
app.get('/api/logs', (req, res) => {
  res.json(logs.slice(-100));
});

app.listen(PORT, () => {
  console.log(`Agent Gate listening on port ${PORT}`);
});
