# Obot Architecture Overview

## Frontend to MCP Connection Flow

### 1. **Frontend (User UI) - SvelteKit Application**
   - **Location**: `ui/user/`
   - **Key Files**:
     - `ui/user/src/lib/services/chat/index.ts` - Main chat service
     - `ui/user/src/lib/services/chat/operations.ts` - API operations
     - `ui/user/src/lib/services/chat/mcp.ts` - MCP-specific operations
     - `ui/user/src/routes/mcp-servers/+page.svelte` - MCP server management UI

### 2. **Data Flow: Frontend → Backend → MCP**

```
User UI (SvelteKit)
    ↓ HTTP/REST API
Backend API (Go)
    ↓
ChatService.createProjectMCP()
    ↓
Backend Handler: ProjectMCPHandler
    ↓
MCP Gateway (/mcp-connect/{mcp_id})
    ↓
MCP Session Manager
    ↓
MCP Servers (via MCP Protocol)
```

### 3. **Key API Endpoints for MCP Integration**

**Project MCP Management:**
- `POST /api/assistants/{assistant_id}/projects/{project_id}/mcpservers` - Create/connect MCP to project
- `GET /api/assistants/{assistant_id}/projects/{project_id}/mcpservers` - List MCPs for project
- `POST /api/assistants/{assistant_id}/projects/{project_id}/mcpservers/{id}/launch` - Launch MCP server

**MCP Gateway (for actual MCP protocol communication):**
- `/mcp-connect/{mcp_id}` - WebSocket/SSE connection for MCP protocol

**Chat Invocation:**
- `POST /api/assistants/{id}/projects/{project_id}/threads/{thread_id}/invoke` - Send chat message

### 4. **How Chat Works with MCPs**

1. **User connects MCP to Project:**
   - User browses MCP catalog at `/mcp-servers`
   - Clicks "Chat" or "Add To Chat" on an MCP server
   - Frontend calls `createProjectMcp()` which creates a ProjectMCP relationship
   - MCP server is launched if needed

2. **User sends chat message:**
   - Frontend sends POST to `/api/assistants/{id}/projects/{project_id}/threads/{thread_id}/invoke`
   - Backend `AssistantHandler.Invoke()` processes the request
   - Calls `invoker.Thread()` which uses Langgraph to execute
   - Langgraph calls MCP tools via `mcp.SessionManager.Run()`
   - MCP tools are executed through the MCP Gateway

3. **Real-time Updates:**
   - Frontend opens SSE connection: `GET /api/assistants/{id}/projects/{project_id}/threads/{thread_id}/events`
   - Backend streams `types.Progress` events as the chat executes
   - Frontend converts progress events to messages via `buildMessagesFromProgress()`

## Backend Architecture

### Core Components

1. **API Server** (`pkg/api/server/`)
   - HTTP server built on Go's standard library
   - Routes defined in `pkg/api/router/router.go`
   - Uses Kubernetes-style API patterns

2. **Handlers** (`pkg/api/handlers/`)
   - `assistants.go` - Chat/assistant operations
   - `modelprovider.go` - Model provider management
   - `mcp.go` - MCP server management
   - `projectmcp.go` - Project-MCP relationships
   - `mcpgateway/` - MCP protocol gateway

3. **Invoker** (`pkg/invoke/invoker.go`)
   - Uses **Langgraph** for orchestration
   - Langgraph is a framework for building stateful, multi-actor applications with LLMs
   - Handles tool calling, MCP integration, and execution flow
   - Key method: `Thread()` - executes chat threads

4. **MCP Integration** (`pkg/mcp/`)
   - `SessionManager` - Manages MCP client sessions
   - `runner.go` - Executes MCP tool calls
   - Gateway handles MCP protocol (JSON-RPC over stdio/HTTP)

5. **Storage** (`pkg/storage/`)
   - Kubernetes CRDs (Custom Resource Definitions)
   - Stores: Agents, Threads, Projects, ToolReferences, etc.
   - Uses controller-runtime for Kubernetes API

### Key Data Structures

- **Agent** (`v1.Agent`) - Assistant definition
- **Thread** (`v1.Thread`) - Chat conversation thread
- **Project** - User-created assistant instance (stored as Thread with `Spec.Project = true`)
- **ToolReference** - MCP servers and model providers
- **ProjectMCP** - Links MCP servers to projects

## Model Provider Configuration

### How Model Providers Work

1. **Model Providers are ToolReferences** with type `model-provider`
2. **Configuration happens in Admin UI** at `/admin/model-providers`
3. **Environment Variables** can auto-configure:
   - `OPENAI_API_KEY` → auto-configures `openai-model-provider`
   - `ANTHROPIC_API_KEY` → auto-configures `anthropic-model-provider`

### Why Only One Provider Shows

**The issue:** Setting `ANTHROPIC_API_KEY` as an environment variable doesn't immediately make it appear in the UI. Here's why:

1. **Auto-configuration happens on server startup** via `EnsureAnthropicCredentialAndDefaults()`
2. **The model provider ToolReference must exist** in the system first
3. **The provider must be "configured"** - meaning credentials are stored
4. **The provider must be in the allowed list** for the assistant/project

### Solution: Configure via Admin UI

1. **Go to Admin UI**: `/admin/model-providers`
2. **Find Anthropic provider** in the list
3. **Click "Configure"** button
4. **Enter your API key** (or it may auto-populate from env var)
5. **Save** - this creates the credential in the system

Alternatively, if you set the env var, you may need to:
- **Restart the Obot server** for it to pick up the env var
- **Wait for the controller** to sync (can take a few seconds)

### Model Provider API Flow

```
Admin UI: /admin/model-providers
    ↓
GET /api/model-providers (global list)
    ↓
Backend: ModelProviderHandler.List()
    ↓
Queries ToolReference CRDs with type=model-provider
    ↓
Checks credentials via GPTClient.ListCredentials()
    ↓
Returns list with "configured" status
```

For project-specific providers:
```
Project Settings: Model Providers
    ↓
GET /api/assistants/{id}/projects/{project_id}/model-providers
    ↓
Backend filters by agent.AllowedModelProviders
    ↓
Returns only allowed providers
```

## Key Files Reference

### Frontend
- `ui/user/src/lib/services/chat/index.ts` - Chat service entry point
- `ui/user/src/lib/services/chat/operations.ts` - All API calls
- `ui/user/src/lib/services/chat/mcp.ts` - MCP helper functions
- `ui/user/src/routes/mcp-servers/+page.svelte` - MCP server browser
- `ui/user/src/routes/admin/model-providers/+page.svelte` - Model provider config

### Backend
- `pkg/api/router/router.go` - All API routes
- `pkg/api/handlers/assistants.go` - Chat/thread handlers
- `pkg/api/handlers/modelprovider.go` - Model provider handlers
- `pkg/api/handlers/projectmcp.go` - Project-MCP handlers
- `pkg/invoke/invoker.go` - Langgraph execution engine
- `pkg/mcp/runner.go` - MCP tool execution
- `pkg/controller/handlers/toolreference/toolreference.go` - Auto-config from env vars

## Summary

- **Langgraph** - Uses Langgraph for orchestration
- **MCP Integration** - Via MCP Gateway and Session Manager
- **Model Providers** - Must be configured in Admin UI, even if env vars are set
- **Real-time Updates** - SSE events stream progress to frontend
- **Storage** - Kubernetes CRDs for all resources

