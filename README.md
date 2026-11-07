# Agent Gate

Control plane for agent credentials. Agents get narrow keys. Real credentials stay on the server. Every action is checked, logged, and revocable.

## MCP Connection

Point any MCP client at:

```
https://YOUR-APP.onrender.com/mcp
```

Send the agent key as:

```
Authorization: Bearer YOUR_AGENT_KEY
```

### Claude Desktop / Cursor example config

```json
{
  "mcpServers": {
    "agent-gate": {
      "url": "https://YOUR-APP.onrender.com/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_AGENT_KEY"
      }
    }
  }
}
```

## Available Tools

- `s3_list`, `s3_get`, `s3_put`, `s3_delete`
- `github_get`, `github_create_issue`, `github_list_prs`
- `slack_post`, `slack_list_channels`
- `http_get`

## Environment Variables

- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_REGION` or `AWS_DEFAULT_REGION`
- `GITHUB_TOKEN`
- `SLACK_BOT_TOKEN`
- `ADMIN_PASSWORD` (login password, default `changeme`)

## Permissions

Free-form, comma-separated. Supports `*` wildcards.

Examples: `read`, `list`, `put`, `post`, `*`, `s3:list`
