# Langgraph Migration Plan - Backend API Changes

This document outlines all the backend API sections that need to be changed to replace GPTScript with a Langgraph Server that can interact with MCPs.

## Overview

The migration involves replacing GPTScript (a Go-based scripting language for LLM interactions) with Langgraph (a Python-based framework for building stateful, multi-actor applications with LLMs). The Langgraph server will need to:
- Execute chat threads and agent workflows
- Integrate with MCP tools via the existing MCP Gateway
- Stream real-time progress events
- Handle tool calling and state management

## 1. Core Components to Replace

### 1.1 Invoker (`pkg/invoke/invoker.go`)

**Current State:**
- Uses `*gptscript.GPTScript` client
- Methods: `Thread()`, `Agent()`, `doRun()`
- Executes via `gptClient.Run()`, `gptClient.Evaluate()`
- Streams events from `gptscript.Run.Events()`
- Manages state via `gptscript.Run` objects

**Changes Required:**
- Replace `gptClient *gptscript.GPTScript` with Langgraph client interface
- Create new Langgraph client that communicates with Langgraph server (likely HTTP/gRPC)
- Replace `gptscript.Options` with Langgraph execution options
- Replace `gptscript.Run` with Langgraph execution state
- Replace `gptscript.ToolDef` with Langgraph tool definitions
- Update event streaming to use Langgraph event format
- Update state management to work with Langgraph state

**Key Methods to Update:**
- `NewInvoker()` - Accept Langgraph client instead of GPTScript client
- `doRun()` (lines 650-770) - Replace GPTScript execution calls
- `stream()` (lines 1002-1153) - Update event handling for Langgraph events
- `saveState()` (lines 772-802) - Update state persistence for Langgraph
- `watchThreadAbort()` (lines 1155-1174) - Update abort mechanism

**Dependencies:**
- `gptscript.Run` → Langgraph execution state
- `gptscript.Options` → Langgraph execution options
- `gptscript.ToolDef` → Langgraph tool definitions
- `gptscript.EventType*` → Langgraph event types

### 1.2 Service Configuration (`pkg/services/config.go`)

**Current State:**
- `newGPTScript()` function (lines 286-342) initializes GPTScript server
- Creates embedded GPTScript server or connects to external URL
- Configures MCP integration via `MCPRunner` and `MCPLoader`
- Sets up credential store integration

**Changes Required:**
- Replace `newGPTScript()` with `newLanggraphServer()` or similar
- Configure Langgraph server connection (HTTP/gRPC endpoint)
- Ensure MCP integration is passed to Langgraph server
- Update credential store integration if needed
- Replace `GPTClient *gptscript.GPTScript` in Services struct with Langgraph client

**Key Changes:**
- Line 141: `GPTClient *gptscript.GPTScript` → Langgraph client type
- Line 463: `newGPTScript()` call → `newLanggraphServer()` call
- Lines 469-479: Credential creation may need updates
- Lines 628-641: Service initialization updates

### 1.3 API Server (`pkg/api/server/server.go`)

**Current State:**
- Stores `gptClient *gptscript.GPTScript` in Server struct
- Passes GPTScript client to API context via `req.GPTClient`

**Changes Required:**
- Replace `gptClient *gptscript.GPTScript` with Langgraph client
- Update `NewServer()` constructor
- Update API context to use Langgraph client (may rename field)

**Key Changes:**
- Line 36: `gptClient *gptscript.GPTScript` → Langgraph client
- Line 47: Constructor parameter update
- Line 181: `GPTClient: s.gptClient` → Langgraph client

### 1.4 API Request Context (`pkg/api/request.go`)

**Current State:**
- `GPTClient *gptscript.GPTScript` field in Context

**Changes Required:**
- Replace with Langgraph client or rename/restructure
- Update all handlers that use `req.GPTClient`

## 2. API Handlers

### 2.1 Assistant Handler (`pkg/api/handlers/assistants.go`)

**Current State:**
- Uses `invoker.Thread()` which internally uses GPTScript
- No direct GPTScript usage in this handler

**Changes Required:**
- Minimal changes if invoker interface remains the same
- May need updates if response format changes

**Key Methods:**
- `Invoke()` (lines 80-152) - Should work with updated invoker

### 2.2 Agent Handler (`pkg/api/handlers/agent.go`)

**Current State:**
- `Script()` method (lines 807-845) uses GPTScript directly
- Converts tools to `gptscript.ToolDef` format
- Uses `req.GPTClient.Fmt()` to format script

**Changes Required:**
- Replace `Script()` method to work with Langgraph
- Update tool definition conversion
- Replace `gptscript.ToolDefsToNodes()` with Langgraph equivalent
- Replace `req.GPTClient.Fmt()` with Langgraph formatting

**Key Changes:**
- Line 832: `gptscript.ToolDefsToNodes()` → Langgraph tool conversion
- Line 839: `req.GPTClient.Fmt()` → Langgraph formatting

### 2.3 MCP Handler (`pkg/api/handlers/mcp.go`)

**Current State:**
- Uses `req.GPTClient.ListCredentials()` for credential management
- Multiple credential operations via GPTScript client

**Changes Required:**
- Determine if credentials are managed by Langgraph server or separately
- Update credential operations to use appropriate API
- May need to keep credential management separate from Langgraph

**Key Methods:**
- Multiple credential operations throughout file
- Lines with `req.GPTClient.ListCredentials()`, `CreateCredential()`, `DeleteCredential()`

### 2.4 Model Provider Handler (`pkg/api/handlers/modelprovider.go`)

**Current State:**
- Uses `req.GPTClient.ListCredentials()` for model provider credentials

**Changes Required:**
- Similar to MCP handler - update credential operations

### 2.5 Projects Handler (`pkg/api/handlers/projects.go`)

**Current State:**
- Uses `req.GPTClient.ListCredentials()` for credentials

**Changes Required:**
- Update credential operations

## 3. MCP Integration

### 3.1 MCP Session Manager (`pkg/mcp/mcp.go`)

**Current State:**
- `GPTScriptTools()` method (lines 19-100) converts MCP tools to `gptscript.ToolDef`
- Creates tool definitions with GPTScript-specific format
- Uses `gptscript.ToolDef` structure

**Changes Required:**
- Create `LanggraphTools()` method or update `GPTScriptTools()` to be generic
- Convert MCP tools to Langgraph tool format
- Update tool definition structure to match Langgraph requirements
- Ensure tool metadata is preserved

**Key Changes:**
- Line 19: Method signature and return type
- Lines 77-88: Tool definition structure
- Line 81: Tool instructions format (currently uses `types.MCPInvokePrefix`)

### 3.2 MCP Runner (`pkg/mcp/runner.go`)

**Current State:**
- Executes MCP tool calls
- May be used by GPTScript's MCPRunner interface

**Changes Required:**
- Ensure compatibility with Langgraph's tool calling mechanism
- May need adapter layer if Langgraph uses different tool execution pattern

### 3.3 Render Package (`pkg/render/render.go`)

**Current State:**
- `Agent()` function converts agents to GPTScript format
- Uses `gptscript.ToolDef` structures (line 43, 65, 67)
- Returns `RenderedAgent` with `Tools []gptscript.ToolDef`

**Changes Required:**
- Update `RenderedAgent` struct to use Langgraph tool definitions
- Replace `gptscript.ToolDef` with Langgraph tool type
- Update tool creation logic to match Langgraph format
- Ensure agent properties map correctly to Langgraph

**Key Changes:**
- Line 12: Import statement
- Line 43: `Tools []gptscript.ToolDef` → Langgraph tool type
- Line 65: Tool initialization
- Line 67-77: Main tool definition structure

## 4. Event Streaming

### 4.1 Events Package (`pkg/events/`)

**Current State:**
- `Submit()` method processes GPTScript events
- Converts `gptscript.Program` and `gptscript.Call` to progress events

**Changes Required:**
- Update to handle Langgraph events
- Replace `gptscript.Program` and `gptscript.Call` with Langgraph equivalents
- Ensure event types map correctly

**Key Files:**
- Check `pkg/events/emitter.go` for event processing

### 4.2 Progress Types (`apiclient/types/`)

**Current State:**
- `types.Progress` may reference GPTScript-specific structures

**Changes Required:**
- Ensure progress types are generic or update for Langgraph
- Check for GPTScript-specific fields

## 5. Tool Resolution

### 5.1 Tools Package (`pkg/tools/resolve.go`)

**Current State:**
- `ResolveToolReferences()` uses `gptscript.GPTScript` client
- Uses `gptscript.Tool` type

**Changes Required:**
- Update to use Langgraph client or tool resolution API
- Replace `gptscript.Tool` with Langgraph tool type

**Key Changes:**
- Line 17: Function signature
- Line 126: `isValidTool()` uses `gptscript.Tool`

## 6. Controller Handlers

### 6.1 ToolReference Handler (`pkg/controller/handlers/toolreference/toolreference.go`)

**Current State:**
- Uses `gptClient *gptscript.GPTScript` for tool resolution
- Resolves tools from registries

**Changes Required:**
- Update to use Langgraph client or separate tool resolution service
- May need to keep tool resolution separate from execution

**Key Changes:**
- Line 56: `gptClient *gptscript.GPTScript` field
- Line 64: Constructor parameter

## 7. State Management

### 7.1 Run State (`pkg/invoke/invoker.go`)

**Current State:**
- Uses `gptscript.Run` for execution state
- Checks `gptscript.Continue` state
- Uses `gptscript.RunState` types

**Changes Required:**
- Replace with Langgraph execution state
- Map Langgraph states to internal state types
- Update state persistence logic

**Key Changes:**
- Line 239: `gptscript.Continue` state check
- Line 816: State terminal check
- Line 930: Error state handling

## 8. Configuration and Environment

### 8.1 Environment Variables

**Current State:**
- `GPTSCRIPT_URL` - GPTScript server URL
- `GPTSCRIPT_CACHE_DIR` - Cache directory
- `GPTSCRIPT_CREDENTIAL_OVERRIDE` - Credential overrides
- `GPTSCRIPT_SYSTEM_TOOLS_DIR` - System tools directory
- `GPTSCRIPT_MODEL_PROVIDER_PROXY_URL` - Model provider proxy
- Various `GPTSCRIPT_*` env vars passed to execution

**Changes Required:**
- Replace with `LANGGRAPH_*` equivalents
- Update environment variable names throughout codebase
- Ensure model provider proxy integration works with Langgraph

**Key Locations:**
- `pkg/services/config.go` - Environment variable usage
- `pkg/invoke/invoker.go` - Environment variables passed to execution (lines 686-708)

## 9. Type Definitions

### 9.1 Import Statements

**Files to Update:**
- All files importing `github.com/gptscript-ai/go-gptscript`
- All files importing `github.com/gptscript-ai/gptscript/pkg/types`
- Replace with Langgraph equivalents

**Key Files:**
- `pkg/invoke/invoker.go` - Line 15
- `pkg/api/handlers/assistants.go` - Line 11
- `pkg/api/handlers/agent.go` - GPTScript imports
- `pkg/api/handlers/mcp.go` - Line 15
- `pkg/api/server/server.go` - Line 11
- `pkg/services/config.go` - Lines 17-20
- `pkg/mcp/mcp.go` - Lines 11-12
- `pkg/tools/resolve.go` - Line 10
- `pkg/api/request.go` - Line 12

### 9.2 Type Replacements

**GPTScript Types → Langgraph Equivalents:**
- `gptscript.GPTScript` → Langgraph client type
- `gptscript.Run` → Langgraph execution state
- `gptscript.Options` → Langgraph execution options
- `gptscript.ToolDef` → Langgraph tool definition
- `gptscript.Tool` → Langgraph tool
- `gptscript.Program` → Langgraph program/graph
- `gptscript.Call` → Langgraph call/step
- `gptscript.RunState` → Langgraph execution state enum
- `gptscript.EventType*` → Langgraph event types

## 10. Implementation Strategy

### Phase 1: Langgraph Server Setup
1. Set up Langgraph server (Python service)
2. Create HTTP/gRPC API for Langgraph operations
3. Implement MCP tool integration in Langgraph server
4. Implement event streaming from Langgraph server

### Phase 2: Client Interface
1. Create Go client for Langgraph server
2. Define interfaces matching current invoker interface
3. Implement tool definition conversion
4. Implement event conversion

### Phase 3: Core Replacement
1. Replace invoker implementation
2. Update service configuration
3. Update API server setup
4. Update request context

### Phase 4: Handler Updates
1. Update agent handler (Script method)
2. Update credential operations (if needed)
3. Update tool resolution

### Phase 5: MCP Integration
1. Update MCP tool conversion
2. Ensure MCP runner compatibility
3. Test MCP tool execution

### Phase 6: Event Streaming
1. Update event processing
2. Ensure progress events work correctly
3. Test real-time updates

### Phase 7: Testing & Cleanup
1. Remove GPTScript dependencies
2. Update tests
3. Update documentation

## 11. Key Considerations

### 11.1 Langgraph Server Architecture
- **Communication Protocol**: HTTP REST API or gRPC?
- **State Management**: How does Langgraph manage execution state?
- **Tool Integration**: How to pass MCP tools to Langgraph?
- **Event Streaming**: SSE, WebSocket, or polling?

### 11.2 MCP Tool Integration
- Langgraph server needs access to MCP Gateway
- Tool definitions must be converted to Langgraph format
- Tool execution must route through MCP Gateway
- Tool metadata must be preserved

### 11.3 Credential Management
- Determine if credentials are managed by Langgraph or separately
- May need to keep credential management in Go layer
- Ensure OAuth flows continue to work

### 11.4 Model Provider Integration
- Langgraph needs access to model provider proxy
- Ensure model provider configuration is passed correctly
- Test with different model providers

### 11.5 State Persistence
- Langgraph execution state must be saved to database
- State must be resumable
- Chat history must be preserved

## 12. Files Requiring Changes

### High Priority (Core Functionality)
1. `pkg/invoke/invoker.go` - Core execution engine
2. `pkg/services/config.go` - Service initialization
3. `pkg/api/server/server.go` - API server setup
4. `pkg/api/request.go` - Request context
5. `pkg/mcp/mcp.go` - MCP tool conversion

### Medium Priority (Handlers)
6. `pkg/api/handlers/agent.go` - Script generation
7. `pkg/api/handlers/mcp.go` - Credential operations
8. `pkg/api/handlers/modelprovider.go` - Credential operations
9. `pkg/api/handlers/projects.go` - Credential operations
10. `pkg/tools/resolve.go` - Tool resolution

### Lower Priority (Supporting)
11. `pkg/controller/handlers/toolreference/toolreference.go` - Tool reference handling
12. `pkg/render/render.go` - Tool/agent rendering (uses `gptscript.ToolDef`)
13. `pkg/events/` - Event processing (if uses GPTScript types)

## 13. New Files to Create

1. `pkg/langgraph/client.go` - Langgraph client interface and implementation
2. `pkg/langgraph/types.go` - Langgraph type definitions
3. `pkg/langgraph/convert.go` - Conversion utilities (tools, events, etc.)
4. `pkg/langgraph/stream.go` - Event streaming implementation

## 14. Testing Requirements

1. Unit tests for Langgraph client
2. Integration tests for MCP tool execution
3. End-to-end tests for chat flow
4. Event streaming tests
5. State persistence tests
6. Credential management tests

