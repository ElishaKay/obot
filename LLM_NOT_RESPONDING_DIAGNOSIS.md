# LLM Not Responding - Diagnosis Guide

## Problem
The LLM doesn't respond, causing timeouts. The issue is likely in the API call chain, not the timeout itself.

## LLM Call Flow

1. **GPTScript makes LLM call** → Uses `GPTSCRIPT_MODEL_PROVIDER_PROXY_URL` env var
2. **Calls LLM Proxy** → `http://localhost:8080/api/llm-proxy/{path}`
3. **LLM Proxy Handler** → `pkg/gateway/server/llmproxy.go:llmProxy()`
4. **Resolves Model Provider URL** → `dispatcher.URLForModelProvider()`
5. **Proxies to Model Provider** → Forwards request to actual LLM API

## Potential Issues

### Issue 1: `internalServerURL` is hardcoded to localhost

**Location**: `pkg/invoke/invoker.go:69`
```go
internalServerURL: fmt.Sprintf("http://localhost:%d", serverPort),
```

**Problem**: In Docker, if GPTScript runs in a different network context, `localhost` might not resolve correctly.

**Fix**: Use an environment variable or configuration option:
```go
internalServerURL := os.Getenv("OBOT_INTERNAL_SERVER_URL")
if internalServerURL == "" {
    internalServerURL = fmt.Sprintf("http://localhost:%d", serverPort)
}
```

### Issue 2: Model Provider Not Configured

**Check**: Verify the model provider is configured:
- Check if `OPENAI_API_KEY` or `ANTHROPIC_API_KEY` is set
- Check if the model provider ToolReference exists in the database
- Check logs for "failed to get model provider" errors

### Issue 3: Model Provider URL Resolution Fails

**Location**: `pkg/gateway/server/dispatcher/dispatcher.go:urlForProvider()`

**Problem**: The dispatcher tries to start the model provider as a system task, which might fail.

**Check**: Look for errors in logs related to:
- "failed to get provider"
- "failed to start provider"
- System task failures

### Issue 4: LLM Proxy Endpoint Not Accessible

**Check**: Verify the endpoint is registered:
- Should be at `POST /api/llm-proxy/{path...}`
- Registered in `pkg/gateway/server/router.go:83`
- Added via `services.GatewayServer.AddRoutes()` in `pkg/api/router/router.go:726`

### Issue 5: Network Configuration in Docker

**Check**: In docker-compose.yaml, verify:
- Services are on the same network (`obot-network`)
- Port 8080 is exposed correctly
- No firewall rules blocking localhost connections

## Diagnostic Steps

1. **Check if LLM proxy endpoint is accessible**:
   ```bash
   docker exec obot curl -X POST http://localhost:8080/api/llm-proxy/v1/chat/completions \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"model":"gpt-4.1","messages":[{"role":"user","content":"test"}]}'
   ```

2. **Check model provider configuration**:
   - Look for ToolReference with type `model-provider`
   - Verify credentials are set
   - Check if model provider daemon is running

3. **Check logs for specific errors**:
   - "failed to get model provider"
   - "failed to get model provider url"
   - "model provider not configured"
   - Connection errors to LLM APIs

4. **Verify environment variables**:
   ```bash
   docker exec obot env | grep -E "OPENAI_API_KEY|ANTHROPIC_API_KEY|OBOT_SERVER"
   ```

5. **Check if GPTScript can reach the proxy**:
   - Add logging in `llmProxy()` handler to see if requests arrive
   - Check if the proxy receives the request but fails to forward it

## Most Likely Issue

Based on the code, the most likely issue is **Issue 1**: The `internalServerURL` is hardcoded to `localhost`, which might not work correctly in all Docker network configurations.

**Recommended Fix**: Make `internalServerURL` configurable via environment variable, defaulting to localhost for backward compatibility.

## Quick Fix to Test

Add this to your `.env` file or docker-compose.yaml:
```yaml
environment:
  - OBOT_INTERNAL_SERVER_URL=http://obot:8080  # Use service name instead of localhost
```

Then modify `pkg/invoke/invoker.go:69` to:
```go
internalServerURL := os.Getenv("OBOT_INTERNAL_SERVER_URL")
if internalServerURL == "" {
    internalServerURL = fmt.Sprintf("http://localhost:%d", serverPort)
}
```

However, note that GPTScript runs in the same process/container, so `localhost` should work. The real issue might be elsewhere in the chain.

