# Langgraph Integration Summary

## Quick Reference: Key Integration Points

This document provides a quick reference for the main integration points between the Obot backend and Langgraph server.

## 1. Primary Execution Flow

```
Frontend → AssistantHandler.Invoke() 
         → invoker.Thread() 
         → Langgraph Server (HTTP/gRPC)
         → MCP Tools via MCP Gateway
         → Stream Events back
```

## 2. Critical Files for Replacement

### Must Change (Core Execution)
- **`pkg/invoke/invoker.go`** - Main execution engine
  - Replace `gptClient.Run()` / `gptClient.Evaluate()` with Langgraph execution
  - Replace `gptscript.Run` event streaming with Langgraph events
  - Update state management

- **`pkg/services/config.go`** - Service initialization
  - Replace `newGPTScript()` with Langgraph server client setup
  - Update service dependencies

- **`pkg/api/server/server.go`** - API server
  - Replace GPTScript client in Server struct
  - Update request context

### Should Change (Tool Integration)
- **`pkg/mcp/mcp.go`** - MCP tool conversion
  - `GPTScriptTools()` → `LanggraphTools()` or generic conversion
  - Convert MCP tools to Langgraph tool format

- **`pkg/render/render.go`** - Agent/tool rendering
  - Replace `gptscript.ToolDef` with Langgraph tool definitions
  - Update `RenderedAgent` struct

### May Change (Credential Management)
- **`pkg/api/handlers/agent.go`** - Script generation
  - Update `Script()` method for Langgraph format

- **`pkg/api/handlers/mcp.go`** - Credential operations
  - Determine if credentials managed by Langgraph or separately

## 3. Key Data Structures to Replace

| GPTScript Type | Langgraph Equivalent | Used In |
|---------------|---------------------|---------|
| `gptscript.GPTScript` | Langgraph Client | invoker, server, config |
| `gptscript.Run` | Langgraph Execution | invoker (state, events) |
| `gptscript.Options` | Langgraph Options | invoker (execution config) |
| `gptscript.ToolDef` | Langgraph Tool | render, mcp, agent handler |
| `gptscript.Program` | Langgraph Graph | events (program structure) |
| `gptscript.Call` | Langgraph Step | events (call tracking) |

## 4. MCP Integration Points

### Current Flow:
1. MCP tools discovered via `mcp.SessionManager`
2. Converted to `gptscript.ToolDef` via `GPTScriptTools()`
3. Passed to GPTScript execution
4. GPTScript calls MCP tools via `mcp.SessionManager.Run()`

### Required Flow:
1. MCP tools discovered via `mcp.SessionManager` (unchanged)
2. Converted to Langgraph tool format
3. Passed to Langgraph execution
4. Langgraph calls MCP tools via MCP Gateway

**Key File:** `pkg/mcp/mcp.go` - `GPTScriptTools()` method

## 5. Event Streaming

### Current:
- GPTScript streams events via `runResp.Events()` channel
- Events include: `RunStart`, `CallStart`, `CallProgress`, `CallFinish`, `Prompt`
- Converted to `types.Progress` for frontend

### Required:
- Langgraph server must stream similar events
- Event types must map to existing `types.Progress` format
- SSE endpoint must continue to work

**Key File:** `pkg/invoke/invoker.go` - `stream()` method

## 6. State Management

### Current:
- State stored in `gptscript.Run` object
- Saved to database via `gatewayClient.RunState()`
- Chat state compressed and stored

### Required:
- Langgraph execution state must be serializable
- State must be saved/restored from database
- Chat history must be preserved

**Key File:** `pkg/invoke/invoker.go` - `saveState()` method

## 7. Environment Variables

### Replace:
- `GPTSCRIPT_URL` → `LANGGRAPH_URL`
- `GPTSCRIPT_CACHE_DIR` → `LANGGRAPH_CACHE_DIR` (if needed)
- `GPTSCRIPT_MODEL_PROVIDER_PROXY_URL` → `LANGGRAPH_MODEL_PROVIDER_PROXY_URL`

### Keep (MCP/Obot specific):
- `OBOT_*` variables
- MCP-related variables

## 8. New Components Needed

1. **Langgraph Client** (`pkg/langgraph/client.go`)
   - HTTP/gRPC client for Langgraph server
   - Methods: `Execute()`, `Stream()`, `Abort()`
   - Tool definition conversion

2. **Langgraph Types** (`pkg/langgraph/types.go`)
   - Go types matching Langgraph server API
   - Execution options, tool definitions, events

3. **Conversion Utilities** (`pkg/langgraph/convert.go`)
   - MCP tools → Langgraph tools
   - Langgraph events → Progress events
   - State serialization/deserialization

## 9. Testing Checklist

- [ ] Langgraph server can execute simple chat
- [ ] MCP tools are accessible from Langgraph
- [ ] Events stream correctly to frontend
- [ ] State persists and restores correctly
- [ ] Credentials work with Langgraph
- [ ] Model providers work correctly
- [ ] Abort functionality works
- [ ] Multiple concurrent executions work

## 10. Migration Order

1. **Setup Langgraph Server** (external service)
2. **Create Go Client** (new package)
3. **Update Invoker** (core execution)
4. **Update Service Config** (initialization)
5. **Update MCP Integration** (tool conversion)
6. **Update Render** (agent rendering)
7. **Update Handlers** (API endpoints)
8. **Test & Refine**
9. **Remove GPTScript** (cleanup)

