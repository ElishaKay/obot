# GPTScript Scope Analysis

## Answer: GPTScript is Used Broadly, Not Just for Chat

GPTScript is **not** specific to the chat UI. It's the **core execution engine** for all LLM-driven operations in Obot, including MCP tool execution. The modifications to replace GPTScript with Langgraph will affect **all parts of the application** that use LLM orchestration.

## 1. Where GPTScript is Used

### 1.1 Core Execution Engine (`pkg/invoke/invoker.go`)

The `Invoker` struct uses GPTScript as its execution engine and is used by:

#### Chat/Assistant Operations
- **`AssistantHandler.Invoke()`** - User chat messages from the UI
- **`InvokeHandler.Invoke()`** - Direct agent invocation API
- **`AgentHandler`** - Agent management and script generation

#### Workflow Operations
- **`TaskHandler`** - Workflow execution (`invoker.Workflow()`)
- **`WorkflowStep` controller** - Individual workflow step execution (`invoker.Step()`)
- **`WorkflowExecution` controller** - Workflow execution management

#### System Tasks
- **`SystemTask()`** - System-level tool execution
- **`EphemeralThreadTask()`** - Ephemeral task execution

#### Knowledge Management
- **`KnowledgeFile` controller** - File ingestion, loading, deletion
- **`KnowledgeSet` controller** - Knowledge set operations
- **`KnowledgeSource` controller** - Knowledge source management

#### Provider Validation
- **`ModelProviderHandler`** - Model provider validation
- **`FileScannerProviderHandler`** - File scanner provider validation

#### OAuth Operations
- **`OAuthAppLogin` controller** - OAuth flow handling

#### Thread Operations
- **`Threads` controller** - Thread management operations

### 1.2 MCP Integration Points

#### Direct MCP Tool Execution
- **`pkg/mcp/runner.go`** - `Run()` method implements GPTScript's `engine.Context` interface
  - **This is called BY GPTScript** when MCP tools need to be executed
  - The comment on line 14 explicitly states: "This method is called by GPTScript"
  - This is the **primary way MCP tools are executed** when called by LLMs

#### MCP Tool Conversion
- **`pkg/mcp/mcp.go`** - `GPTScriptTools()` converts MCP tools to `gptscript.ToolDef` format
  - Used by `pkg/render/render.go` to include MCP tools in agent definitions
  - All MCP tools that are used by LLMs go through this conversion

#### MCP Server Configuration
- **`pkg/services/config.go`** - GPTScript is initialized with:
  - `MCPRunner: mcpSessionManager` - For executing MCP tools
  - `MCPLoader: mcpSessionManager` - For loading MCP tools

### 1.3 Direct MCP Access (Without GPTScript)

Some MCP operations **do not** go through GPTScript:

- **`pkg/api/handlers/mcp.go`** - `GetTools()` directly queries MCP servers
  - Used for browsing/listing available tools
  - Does not execute tools, only lists them

- **MCP Gateway** (`pkg/api/handlers/mcpgateway/`)
  - Handles direct MCP protocol communication
  - Used for MCP server management, not tool execution

## 2. Execution Flow

### When LLM Executes MCP Tools:
```
User Chat/Workflow/System Task
    ↓
Invoker (uses GPTScript)
    ↓
GPTScript orchestrates LLM calls
    ↓
LLM requests MCP tool execution
    ↓
GPTScript calls mcp.SessionManager.Run()
    ↓
MCP Gateway executes tool
    ↓
Result returned to GPTScript
    ↓
GPTScript continues orchestration
```

### When Browsing MCP Tools (No GPTScript):
```
User browses MCP servers
    ↓
MCPHandler.GetTools()
    ↓
Direct MCP client query
    ↓
Returns tool list
```

## 3. Impact of Replacing GPTScript with Langgraph

### Must Change (All LLM-Driven Operations)

1. **Core Execution** (`pkg/invoke/invoker.go`)
   - Affects: Chat, Workflows, System Tasks, Knowledge Operations, Provider Validation, OAuth

2. **MCP Tool Execution** (`pkg/mcp/runner.go`)
   - Currently implements GPTScript's `engine.Context` interface
   - Must be adapted to work with Langgraph's tool calling mechanism

3. **MCP Tool Conversion** (`pkg/mcp/mcp.go`)
   - `GPTScriptTools()` must become `LanggraphTools()` or generic conversion
   - All MCP tools used by LLMs go through this

4. **Agent Rendering** (`pkg/render/render.go`)
   - Converts agents to GPTScript format
   - Must convert to Langgraph format

5. **Service Configuration** (`pkg/services/config.go`)
   - GPTScript initialization with MCP integration
   - Must initialize Langgraph with MCP integration

### May Not Need Changes (Direct MCP Access)

1. **MCP Tool Browsing** (`pkg/api/handlers/mcp.go` - `GetTools()`)
   - Direct MCP queries, no LLM involved
   - Should continue to work as-is

2. **MCP Gateway** (`pkg/api/handlers/mcpgateway/`)
   - Direct MCP protocol handling
   - Should continue to work as-is

3. **MCP Server Management**
   - CRUD operations for MCP servers
   - No LLM involvement

## 4. Key Insight

**MCP tools are executed in two ways:**

1. **Direct Execution** (No GPTScript/Langgraph needed)
   - Tool browsing, server management
   - Uses MCP Gateway directly
   - **These will NOT be affected by the migration**

2. **LLM-Driven Execution** (Requires GPTScript/Langgraph)
   - When an LLM decides to call an MCP tool
   - Goes through: LLM → GPTScript/Langgraph → MCP Runner → MCP Gateway
   - **These WILL be affected by the migration**

## 5. Conclusion

**The GPTScript → Langgraph migration affects:**

✅ **All chat operations** (user UI)
✅ **All workflow operations**
✅ **All system tasks**
✅ **All knowledge management operations**
✅ **All provider validation**
✅ **All OAuth flows that use LLMs**
✅ **All MCP tool execution when called by LLMs**

❌ **Does NOT affect:**
- Direct MCP tool browsing/listing
- MCP server management (CRUD)
- MCP Gateway protocol handling (when not called by LLMs)

**The migration is comprehensive** - it's not just about chat, but about replacing the entire LLM orchestration engine that powers all AI-driven features in Obot.

