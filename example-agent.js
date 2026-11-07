// Example agent that calls the gate on its own.
// Usage: node example-agent.js <gate-url> <agent-key> <action> <resource>
// Example: node example-agent.js https://your-app.onrender.com YOUR_KEY read my-bucket

const [,, gateUrl, key, action, resource] = process.argv;

if (!gateUrl || !key || !action) {
  console.error('Usage: node example-agent.js <gate-url> <agent-key> <action> [resource]');
  process.exit(1);
}

async function main() {
  const res = await fetch(`${gateUrl.replace(/\/$/, '')}/api/gate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key, action, resource })
  });
  const data = await res.json();
  console.log(JSON.stringify(data, null, 2));
  if (!res.ok) process.exit(1);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
