# Using OBOT_BOOTSTRAP_TOKEN Header for MCP Server Access

## Overview

You can now connect to obot-hosted MCP servers from any client using the `OBOT_BOOTSTRAP_TOKEN` header, bypassing Google OAuth and cookie-based authentication. This is useful for programmatic access, CI/CD pipelines, or external MCP clients.

## How It Works

The implementation supports three authentication methods (in order of precedence):

1. **`OBOT_BOOTSTRAP_TOKEN` header** (new) - Direct header authentication
2. **`Authorization: Bearer <token>` header** - Standard Bearer token
3. **`obot-bootstrap` cookie** - Cookie-based authentication

When authenticated via bootstrap token, users are granted Owner-level access and can bypass MCP server access control checks, allowing access to any MCP server.

## Usage

### Getting Your Bootstrap Token

The bootstrap token is either:
- Set via the `OBOT_BOOTSTRAP_TOKEN` environment variable when starting the server
- Auto-generated on first startup and printed to the console
- Stored in the credential system and reused on subsequent startups

To retrieve it:
```bash
# If using Kubernetes/Helm
kubectl get secret -n <namespace> <helm-install-name>-config -ojson | jq -r .data.OBOT_BOOTSTRAP_TOKEN | base64 -d; echo

# Or check server logs for the printed token
```

### Connecting to MCP Servers

#### Using curl

```bash
# Set your bootstrap token
export OBOT_BOOTSTRAP_TOKEN="your-token-here"

# Connect to an MCP server
curl -H "OBOT_BOOTSTRAP_TOKEN: $OBOT_BOOTSTRAP_TOKEN" \
     -H "Content-Type: application/json" \
     https://your-obot-instance.com/mcp-connect/your-mcp-server-id
```

#### Using the Authorization Header (also supported)

```bash
curl -H "Authorization: Bearer $OBOT_BOOTSTRAP_TOKEN" \
     -H "Content-Type: application/json" \
     https://your-obot-instance.com/mcp-connect/your-mcp-server-id
```

#### Using an MCP Client

When configuring an MCP client (like Claude Desktop, Cursor, etc.), you can add the header:

```json
{
  "mcpServers": {
    "your-server": {
      "url": "https://your-obot-instance.com/mcp-connect/your-mcp-server-id",
      "headers": {
        "OBOT_BOOTSTRAP_TOKEN": "your-token-here"
      }
    }
  }
}
```

### Example: Python Client

```python
import requests

bootstrap_token = "your-token-here"
mcp_server_id = "your-mcp-server-id"
obot_url = "https://your-obot-instance.com"

headers = {
    "OBOT_BOOTSTRAP_TOKEN": bootstrap_token,
    "Content-Type": "application/json"
}

# Connect to MCP server
response = requests.post(
    f"{obot_url}/mcp-connect/{mcp_server_id}",
    headers=headers,
    json={
        "jsonrpc": "2.0",
        "method": "initialize",
        "id": 1,
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "my-client",
                "version": "1.0.0"
            }
        }
    }
)
```

## Security Considerations

1. **Bootstrap Token Access**: Bootstrap tokens grant Owner-level access, which bypasses all MCP access control checks. Use with caution.

2. **Token Storage**: Store bootstrap tokens securely:
   - Never commit tokens to version control
   - Use environment variables or secret management systems
   - Rotate tokens regularly

3. **Bootstrap Mode**: 
   - **Header-based authentication** (`OBOT_BOOTSTRAP_TOKEN` or `Authorization: Bearer`): Works even when admins exist and Google OAuth is configured. This allows programmatic MCP access without requiring bootstrap mode to be enabled.
   - **Cookie-based authentication**: Only works when bootstrap mode is enabled (no non-bootstrap admin users exist, or `OBOT_SERVER_FORCE_ENABLE_BOOTSTRAP=true` is set). This restriction applies to UI login.

4. **HTTPS**: Always use HTTPS in production to protect the token in transit.

5. **Bypassing Access Control**: When authenticated via bootstrap token headers, users bypass all MCP access control checks and can access any MCP server, regardless of workspace/catalog permissions.

## Limitations

- **Header-based authentication** (recommended for MCP access): Works even when admins exist and OAuth is configured
- **Cookie-based authentication**: Only works when bootstrap mode is enabled (no other admin users exist, or force-enabled)
- The bootstrap user bypasses all MCP access control rules
- This is intended for administrative/programmatic access, not regular user access

## Troubleshooting

### Token Not Working

1. **For header-based auth**: You don't need bootstrap mode enabled - it works even when admins exist. However, you can verify the token is valid by checking server logs or credentials.

2. **For cookie-based auth**: Verify bootstrap mode is enabled:
   ```bash
   curl https://your-obot-instance.com/api/bootstrap/enabled
   ```

3. Check that the token matches the server's stored token

4. Ensure authentication is enabled on the server (`OBOT_SERVER_ENABLE_AUTHENTICATION=true`)

5. Verify you're using the correct header name: `OBOT_BOOTSTRAP_TOKEN` (case-sensitive)

### Access Denied

- Verify you're using the correct MCP server ID
- Check that the server exists and is not a template
- Ensure the header name is exactly `OBOT_BOOTSTRAP_TOKEN` (case-sensitive)

## Implementation Details

The changes made:

1. **`pkg/bootstrap/bootstrap.go`**: Modified `AuthenticateRequest` to accept `OBOT_BOOTSTRAP_TOKEN` header
2. **`pkg/api/authz/mcpid.go`**: Added bypass for bootstrap users in MCP authorization checks

These changes allow bootstrap-authenticated users to access any MCP server without going through the normal access control checks.

