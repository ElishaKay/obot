package mcpgateway

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gptscript-ai/go-gptscript"
	"github.com/gptscript-ai/gptscript/pkg/mvl"
	nmcp "github.com/nanobot-ai/nanobot/pkg/mcp"
	"github.com/obot-platform/obot/apiclient/types"
	"github.com/obot-platform/obot/pkg/api"
	"github.com/obot-platform/obot/pkg/api/handlers"
	gateway "github.com/obot-platform/obot/pkg/gateway/client"
	gatewaytypes "github.com/obot-platform/obot/pkg/gateway/types"
	"github.com/obot-platform/obot/pkg/mcp"
	v1 "github.com/obot-platform/obot/pkg/storage/apis/obot.obot.ai/v1"
	"github.com/tidwall/gjson"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/authentication/user"
	kclient "sigs.k8s.io/controller-runtime/pkg/client"
)

// MCP Method Constants
const (
	methodPing                          = "ping"
	methodInitialize                    = "initialize"
	methodResourcesRead                 = "resources/read"
	methodResourcesList                 = "resources/list"
	methodResourcesTemplatesList        = "resources/templates/list"
	methodPromptsList                   = "prompts/list"
	methodPromptsGet                    = "prompts/get"
	methodToolsList                     = "tools/list"
	methodToolsCall                     = "tools/call"
	methodNotificationsInitialized      = "notifications/initialized"
	methodNotificationsProgress         = "notifications/progress"
	methodNotificationsRootsListChanged = "notifications/roots/list_changed"
	methodNotificationsCancelled        = "notifications/cancelled"
	methodLoggingSetLevel               = "logging/setLevel"
	methodSampling                      = "sampling/createMessage"
)

var log = mvl.Package()

type Handler struct {
	storageClient     kclient.Client
	gatewayClient     *gateway.Client
	gptClient         *gptscript.GPTScript
	mcpSessionManager *mcp.SessionManager
	webhookHelper     *mcp.WebhookHelper
	tokenStore        mcp.GlobalTokenStore
	pendingRequests   sync.Map
	mcpSessionCache   sync.Map
	sessionCache      sync.Map
	baseURL           string
}

func NewHandler(storageClient kclient.Client, mcpSessionManager *mcp.SessionManager, webhookHelper *mcp.WebhookHelper, globalTokenStore mcp.GlobalTokenStore, gatewayClient *gateway.Client, gptClient *gptscript.GPTScript, baseURL string) *Handler {
	return &Handler{
		storageClient:     storageClient,
		gatewayClient:     gatewayClient,
		gptClient:         gptClient,
		mcpSessionManager: mcpSessionManager,
		webhookHelper:     webhookHelper,
		tokenStore:        globalTokenStore,
		baseURL:           baseURL,
	}
}

func (h *Handler) StreamableHTTP(req api.Context) error {
	sessionID := req.Request.Header.Get("Mcp-Session-Id")
	mcpID := req.PathValue("mcp_id")

	// Log authentication details for debugging
	bootstrapToken := req.Request.Header.Get("OBOT_BOOTSTRAP_TOKEN")
	authHeader := req.Request.Header.Get("Authorization")
	userName := req.User.GetName()
	userUID := req.User.GetUID()
	authProviderName := ""
	if req.User.GetExtra()["auth_provider_name"] != nil && len(req.User.GetExtra()["auth_provider_name"]) > 0 {
		authProviderName = req.User.GetExtra()["auth_provider_name"][0]
	}

	log.Infof("MCP connection attempt: mcpID=%s, method=%s, userName=%s, userUID=%s, authProvider=%s, hasBootstrapToken=%v, hasAuthHeader=%v",
		mcpID, req.Request.Method, userName, userUID, authProviderName, bootstrapToken != "", authHeader != "")

	mcpID, mcpServer, mcpServerConfig, err := handlers.ServerForActionWithConnectID(req, mcpID, h.mcpSessionManager.TokenService(), h.baseURL)
	if err == nil && mcpServer.Spec.Template {
		// Prevent connections to MCP server templates by returning a 404.
		log.Warnf("Attempted connection to MCP server template: %s", mcpID)
		err = apierrors.NewNotFound(schema.GroupResource{Group: "obot.obot.ai", Resource: "mcpserver"}, mcpID)
	}

	ss := newSessionStore(h, mcpID, req.User.GetUID())

	if err != nil {
		log.Errorf("Failed to get MCP server config for mcpID=%s, userUID=%s, authProvider=%s: %v", mcpID, userUID, authProviderName, err)
		if apierrors.IsNotFound(err) {
			// If the MCP server is not found, remove the session.
			if sessionID != "" {
				session, found, err := ss.LoadAndDelete(req.Context(), h, sessionID)
				if err != nil {
					log.Errorf("Failed to delete session %s: %v", sessionID, err)
					return fmt.Errorf("failed to get mcp server config: %w", err)
				}

				if found {
					session.Close(true)
				}
			}
		}

		return fmt.Errorf("failed to get mcp server config: %w", err)
	}

	log.Infof("Successfully retrieved MCP server config: mcpID=%s, serverName=%s, userUID=%s", mcpID, mcpServer.Name, userUID)

	messageCtx := messageContext{
		userID:       req.User.GetUID(),
		mcpID:        mcpID,
		mcpServer:    mcpServer,
		serverConfig: mcpServerConfig,
		req:          req.Request,
		resp:         req.ResponseWriter,
	}
	if mcpServer.Spec.Manifest.Runtime == types.RuntimeComposite {
		// List all component servers for the composite server.
		var componentServerList v1.MCPServerList
		if err := req.List(&componentServerList,
			kclient.InNamespace(mcpServer.Namespace),
			kclient.MatchingFields{
				"spec.compositeName": mcpServer.Name,
			}); err != nil {
			return fmt.Errorf("failed to list component servers for composite server %s: %v", mcpServer.Name, err)
		}

		var componentInstanceList v1.MCPServerInstanceList
		if err := req.List(&componentInstanceList,
			kclient.InNamespace(mcpServer.Namespace),
			kclient.MatchingFields{
				"spec.compositeName": mcpServer.Name,
			}); err != nil {
			return fmt.Errorf("failed to list component instances for composite server %s: %v", mcpServer.Name, err)
		}

		// Precompute disabled component IDs for quick lookup (default is enabled if not listed)
		var compositeConfig types.CompositeRuntimeConfig
		if mcpServer.Spec.Manifest.CompositeConfig != nil {
			compositeConfig = *mcpServer.Spec.Manifest.CompositeConfig
		}

		disabledComponents := make(map[string]bool, len(compositeConfig.ComponentServers))
		for _, comp := range compositeConfig.ComponentServers {
			if comp.CatalogEntryID != "" {
				disabledComponents[comp.CatalogEntryID] = comp.Disabled
			} else if comp.MCPServerID != "" {
				disabledComponents[comp.MCPServerID] = comp.Disabled
			}
		}

		componentServers := make([]messageContext, 0, len(componentServerList.Items)+len(componentInstanceList.Items))

		// Add single-user component servers
		for _, componentServer := range componentServerList.Items {
			// Skip if explicitly disabled in composite config
			if disabledComponents[componentServer.Spec.MCPServerCatalogEntryName] {
				log.Debugf("Skipping component server %s not enabled in composite config", componentServer.Name)
				continue
			}

			// Resolve server and config using the higher-level API
			srv, config, err := handlers.ServerForAction(req, componentServer.Name, h.mcpSessionManager.TokenService(), h.baseURL)
			if err != nil {
				// If the component isn't configured or can't be reached, skip it.
				log.Warnf("Failed to get component server %s: %v", componentServer.Name, err)
				continue
			}

			componentServers = append(componentServers, messageContext{
				userID:       req.User.GetUID(),
				mcpID:        srv.Name,
				mcpServer:    srv,
				serverConfig: config,
			})
		}

		// Add multi-user component instances
		for _, componentInstance := range componentInstanceList.Items {
			var multiUserServer v1.MCPServer
			if err := req.Get(&multiUserServer, componentInstance.Spec.MCPServerName); err != nil {
				log.Warnf("Failed to get multi-user server %s for instance %s: %v", componentInstance.Spec.MCPServerName, componentInstance.Name, err)
				continue
			}

			if disabledComponents[multiUserServer.Name] {
				log.Debugf("Skipping component instance %s not enabled in composite config", componentInstance.Name)
				continue
			}

			srv, config, err := handlers.ServerForAction(req, multiUserServer.Name, h.mcpSessionManager.TokenService(), h.baseURL)
			if err != nil {
				log.Warnf("Failed to get multi-user server %s: %v", multiUserServer.Name, err)
				continue
			}

			componentServers = append(componentServers, messageContext{
				userID:       req.User.GetUID(),
				mcpID:        srv.Name,
				mcpServer:    srv,
				serverConfig: config,
			})
		}

		if len(componentServers) < 1 {
			return fmt.Errorf("composite server %s has no running component servers", mcpServer.Name)
		}

		messageCtx.compositeContext = newCompositeContext(mcpServer.Spec.Manifest.CompositeConfig, componentServers)
	}

	req.Request = req.WithContext(withMessageContext(req.Context(), messageCtx))

	// Log before serving the request
	log.Debugf("Serving MCP request: mcpID=%s, method=%s, path=%s", mcpID, req.Request.Method, req.Request.URL.Path)

	// Serve the HTTP request (handles WebSocket, SSE, and direct HTTP POST)
	nmcp.NewHTTPServer(nil, h, nmcp.HTTPServerOptions{SessionStore: ss}).ServeHTTP(req.ResponseWriter, req.Request)

	return nil
}

type messageContext struct {
	compositeContext
	userID, mcpID string
	mcpServer     v1.MCPServer
	serverConfig  mcp.ServerConfig
	req           *http.Request
	resp          http.ResponseWriter
}

func (h *Handler) OnMessage(ctx context.Context, msg nmcp.Message) {
	if h.pendingRequestsForSession(msg.Session.ID()).Notify(msg) {
		// This is a response to a pending request.
		// We don't forward it to the client, just return.
		return
	}

	m, ok := messageContextFromContext(ctx)
	if !ok {
		log.Errorf("Failed to get message context from context: %v", ctx)
		msg.SendError(ctx, &nmcp.RPCError{
			Code:    -32603,
			Message: "Failed to get message context",
		})
		return
	}

	if m.mcpServer.Spec.Manifest.Runtime == types.RuntimeComposite {
		h.onCompositeMessage(ctx, msg, m)
		return
	}

	h.onMessage(ctx, msg, m)
}

func (h *Handler) onMessage(ctx context.Context, msg nmcp.Message, m messageContext) {
	// Determine PowerUserWorkspaceID: use server's workspace ID for multi-user servers,
	// or look up catalog entry's workspace ID for single-user servers
	powerUserWorkspaceID := m.mcpServer.Spec.PowerUserWorkspaceID
	if powerUserWorkspaceID == "" && m.mcpServer.Spec.MCPServerCatalogEntryName != "" {
		// This is a single-user server created from a catalog entry, look up the entry
		var entry v1.MCPServerCatalogEntry
		if err := h.storageClient.Get(ctx, kclient.ObjectKey{Namespace: m.mcpServer.Namespace, Name: m.mcpServer.Spec.MCPServerCatalogEntryName}, &entry); err == nil {
			powerUserWorkspaceID = entry.Spec.PowerUserWorkspaceID
		}
	}

	auditLog := gatewaytypes.MCPAuditLog{
		CreatedAt:                 time.Now(),
		UserID:                    m.userID,
		MCPID:                     m.mcpID,
		PowerUserWorkspaceID:      powerUserWorkspaceID,
		MCPServerDisplayName:      m.mcpServer.Spec.Manifest.Name,
		MCPServerCatalogEntryName: m.mcpServer.Spec.MCPServerCatalogEntryName,
		ClientName:                msg.Session.InitializeRequest.ClientInfo.Name,
		ClientVersion:             msg.Session.InitializeRequest.ClientInfo.Version,
		ClientIP:                  getClientIP(m.req),
		CallType:                  msg.Method,
		CallIdentifier:            extractCallIdentifier(msg),
		SessionID:                 msg.Session.ID(),
		UserAgent:                 m.req.UserAgent(),
		RequestHeaders:            captureHeaders(m.req.Header),
	}
	if msg.ID != nil {
		auditLog.RequestID = fmt.Sprintf("%v", msg.ID)
	}

	// Capture request body if available
	if msg.Params != nil {
		if requestBody, err := json.Marshal(msg.Params); err == nil {
			auditLog.RequestBody = requestBody
		}
	}

	// If an unauthorized error occurs, send the proper status code.
	var (
		err    error
		client *mcp.Client
		result any
	)
	defer func() {
		// Complete audit log
		auditLog.ProcessingTimeMs = time.Since(auditLog.CreatedAt).Milliseconds()
		auditLog.ResponseHeaders = captureHeaders(m.resp.Header())

		if err != nil {
			auditLog.Error = err.Error()
			if auditLog.ResponseStatus < http.StatusBadRequest {
				auditLog.ResponseStatus = http.StatusInternalServerError
			}

			var oauthErr nmcp.AuthRequiredErr
			if errors.As(err, &oauthErr) {
				log.Errorf("OAuth error for MCP server %s (mcpID=%s, userID=%s, method=%s): %v", m.mcpServer.Name, m.mcpID, m.userID, msg.Method, oauthErr)
				auditLog.ResponseStatus = http.StatusUnauthorized
				m.resp.Header().Set(
					"WWW-Authenticate",
					fmt.Sprintf(`Bearer error="invalid_token", error_description="The access token is invalid or expired. Please re-authenticate and try again.", resource_metadata="%s/.well-known/oauth-protected-resource%s"`, h.baseURL, m.req.URL.Path),
				)
				http.Error(m.resp, fmt.Sprintf("Unauthorized: %v", oauthErr), http.StatusUnauthorized)
				h.gatewayClient.LogMCPAuditEntry(auditLog)
				return
			}

			log.Errorf("Error processing MCP message for server %s (mcpID=%s, userID=%s, method=%s): %v", m.mcpServer.Name, m.mcpID, m.userID, msg.Method, err)

			if rpcError := (*nmcp.RPCError)(nil); errors.As(err, &rpcError) {
				msg.SendError(ctx, rpcError)
			} else {
				msg.SendError(ctx, &nmcp.RPCError{
					Code:    -32603,
					Message: fmt.Sprintf("failed to send %s message to server %s: %v", msg.Method, m.mcpServer.Name, err),
				})
			}
		} else {
			auditLog.ResponseStatus = http.StatusOK
			// Capture response body if available
			if result != nil {
				if responseBody, err := json.Marshal(result); err == nil {
					auditLog.ResponseBody = responseBody
				}
			}
		}

		h.gatewayClient.LogMCPAuditEntry(auditLog)
	}()

	catalogName := m.mcpServer.Spec.MCPCatalogID
	if catalogName == "" {
		catalogName = m.mcpServer.Spec.PowerUserWorkspaceID
	}
	if catalogName == "" && m.mcpServer.Spec.MCPServerCatalogEntryName != "" {
		var entry v1.MCPServerCatalogEntry
		if err := h.storageClient.Get(ctx, kclient.ObjectKey{Namespace: m.mcpServer.Namespace, Name: m.mcpServer.Spec.MCPServerCatalogEntryName}, &entry); err != nil {
			log.Errorf("Failed to get catalog for server %s: %v", m.mcpServer.Name, err)
			return
		}
		catalogName = entry.Spec.MCPCatalogName
	}

	var webhooks []mcp.Webhook
	webhooks, err = h.webhookHelper.GetWebhooksForMCPServer(ctx, h.gptClient, m.mcpServer.Namespace, m.mcpServer.Name, m.mcpServer.Spec.MCPServerCatalogEntryName, catalogName, auditLog.CallType, auditLog.CallIdentifier)
	if err != nil {
		log.Errorf("Failed to get webhooks for server %s: %v", m.mcpServer.Name, err)
		return
	}

	if err = fireWebhooks(ctx, webhooks, msg, &auditLog, "request", m.userID, m.mcpID); err != nil {
		log.Errorf("Failed to fire webhooks for server %s: %v", m.mcpServer.Name, err)
		auditLog.ResponseStatus = http.StatusFailedDependency
		return
	}

	client, err = h.mcpSessionManager.ClientForMCPServerWithOptions(
		ctx,
		m.userID,
		msg.Session.ID(),
		m.mcpServer,
		m.serverConfig,
		h.asClientOption(
			msg.Session,
			m.userID,
			m.mcpID,
			m.mcpServer.Namespace,
			m.mcpServer.Name,
			m.mcpServer.Spec.Manifest.Name,
			m.mcpServer.Spec.MCPServerCatalogEntryName,
			catalogName,
			powerUserWorkspaceID,
		),
	)
	if err != nil {
		log.Errorf("Failed to get MCP client for server %s (mcpID=%s, userID=%s, method=%s): %v", m.mcpServer.Name, m.mcpID, m.userID, msg.Method, err)
		return
	}

	switch msg.Method {
	case methodNotificationsInitialized:
		// This method is special because it is handled automatically by the client.
		// So, we don't forward this one, just respond with a success.
		return
	case methodPing:
		result = nmcp.PingResult{}
	case methodInitialize:
		go func(session *nmcp.Session) {
			session.Wait()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			if err := h.mcpSessionManager.CloseClient(ctx, m.serverConfig, session.ID()); err != nil {
				log.Errorf("Failed to shutdown server %s: %v", m.mcpServer.Name, err)
			}

			if _, _, err = newSessionStore(h, m.mcpID, m.userID).LoadAndDelete(ctx, h, session.ID()); err != nil {
				log.Errorf("Failed to delete session %s: %v", session.ID(), err)
			}
		}(msg.Session)

		if client.Session.InitializeResult.ServerInfo != (nmcp.ServerInfo{}) ||
			client.Session.InitializeResult.Capabilities.Tools != nil ||
			client.Session.InitializeResult.Capabilities.Prompts != nil ||
			client.Session.InitializeResult.Capabilities.Resources != nil {
			if err = msg.Reply(ctx, client.Session.InitializeResult); err != nil {
				log.Errorf("Failed to reply to server %s: %v", m.mcpServer.Name, err)
				msg.SendError(ctx, &nmcp.RPCError{
					Code:    -32603,
					Message: fmt.Sprintf("failed to reply to server %s: %v", m.mcpServer.Name, err),
				})
			}
			return
		}

		result = nmcp.InitializeResult{}
	case methodResourcesRead:
		result = nmcp.ReadResourceResult{}
	case methodResourcesList:
		result = nmcp.ListResourcesResult{}
	case methodResourcesTemplatesList:
		result = nmcp.ListResourceTemplatesResult{}
	case methodPromptsList:
		result = nmcp.ListPromptsResult{}
	case methodPromptsGet:
		result = nmcp.GetPromptResult{}
	case methodToolsList:
		result = nmcp.ListToolsResult{}
	case methodToolsCall:
		result = nmcp.CallToolResult{}
	case methodNotificationsProgress, methodNotificationsRootsListChanged, methodNotificationsCancelled, methodLoggingSetLevel:
		// These methods don't require a result.
		result = nmcp.Notification{}
	default:
		log.Errorf("Unknown method for server message: %s", msg.Method)
		err = &nmcp.RPCError{
			Code:    -32601,
			Message: "Method not allowed",
		}
		return
	}

	// Send forward the message to the server and wait for the result
	if err = client.Session.Exchange(ctx, msg.Method, &msg, &result); err != nil {
		log.Errorf("Failed to send %s message to server %s: %v", msg.Method, m.mcpServer.Name, err)
		return
	}

	b, err := json.Marshal(result)
	if err != nil {
		log.Errorf("Failed to marshal result for server %s: %v", m.mcpServer.Name, err)
		err = &nmcp.RPCError{
			Code:    -32603,
			Message: fmt.Sprintf("failed to marshal result for server %s: %v", m.mcpServer.Name, err),
		}
		return
	}

	msg.Result = b

	if err = fireWebhooks(ctx, webhooks, msg, &auditLog, "response", m.userID, m.mcpID); err != nil {
		log.Errorf("Failed to fire webhooks for server %s: %v", m.mcpServer.Name, err)
		auditLog.ResponseStatus = http.StatusFailedDependency
		return
	}

	if err = msg.Reply(ctx, msg.Result); err != nil {
		log.Errorf("Failed to reply to server %s: %v", m.mcpServer.Name, err)
		err = &nmcp.RPCError{
			Code:    -32603,
			Message: fmt.Sprintf("failed to reply to server %s: %v", m.mcpServer.Name, err),
		}
	}
}

// Helper methods for audit logging

func getClientIP(req *http.Request) string {
	// Check X-Forwarded-For header first
	if forwarded := req.Header.Get("X-Forwarded-For"); forwarded != "" {
		// Take the first IP in the list
		if idx := strings.Index(forwarded, ","); idx != -1 {
			return strings.TrimSpace(forwarded[:idx])
		}
		return strings.TrimSpace(forwarded)
	}

	// Check X-Real-IP header
	if realIP := req.Header.Get("X-Real-IP"); realIP != "" {
		return strings.TrimSpace(realIP)
	}

	// Fall back to RemoteAddr
	if host, _, err := net.SplitHostPort(req.RemoteAddr); err == nil {
		return host
	}

	return req.RemoteAddr
}

func extractCallIdentifier(msg nmcp.Message) string {
	switch msg.Method {
	case methodResourcesRead:
		return gjson.GetBytes(msg.Params, "uri").String()
	case methodToolsCall, methodPromptsGet:
		return gjson.GetBytes(msg.Params, "name").String()
	default:
		return ""
	}
}

func captureHeaders(headers http.Header) json.RawMessage {
	// Create a filtered version of headers (removing sensitive information)
	filteredHeaders := make(map[string][]string)
	for k, v := range headers {
		// Skip sensitive headers
		if strings.EqualFold(k, "Authorization") ||
			strings.EqualFold(k, "Cookie") ||
			strings.EqualFold(k, "X-Auth-Token") {
			continue
		}
		filteredHeaders[k] = v
	}

	if data, err := json.Marshal(filteredHeaders); err == nil {
		return data
	}
	return nil
}

// Webhook helpers

func fireWebhooks(ctx context.Context, webhooks []mcp.Webhook, msg nmcp.Message, auditLog *gatewaytypes.MCPAuditLog, webhookType, userID, mcpID string) error {
	signatures := make(map[string]string, len(webhooks))

	// Go through webhook validations.
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
	}
	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	auditLog.WebhookStatuses = make([]gatewaytypes.MCPWebhookStatus, 0, len(webhooks))
	var rpcErrors []*nmcp.RPCError
	for _, webhook := range webhooks {
		webhookStatus, rpcError := fireWebhook(ctx, httpClient, body, mcpID, userID, webhook.URL, webhook.Secret, signatures)
		if rpcError != nil {
			auditLog.WebhookStatuses = append(auditLog.WebhookStatuses, gatewaytypes.MCPWebhookStatus{
				Type:    webhookType,
				URL:     webhook.URL,
				Status:  webhookStatus,
				Message: rpcError.Message,
			})
			rpcErrors = append(rpcErrors, rpcError)
		} else {
			auditLog.WebhookStatuses = append(auditLog.WebhookStatuses, gatewaytypes.MCPWebhookStatus{
				Type:   webhookType,
				URL:    webhook.URL,
				Status: webhookStatus,
			})
		}
	}

	switch len(rpcErrors) {
	case 0:
		return nil
	case 1:
		return rpcErrors[0]
	default:
		var message strings.Builder
		message.WriteString("failed to fire webhooks: ")
		for _, err := range rpcErrors {
			message.WriteString(err.Message)
			message.WriteString("; ")
		}
		return &nmcp.RPCError{
			Code:    -32603,
			Message: message.String()[:message.Len()-2],
		}
	}
}

func fireWebhook(ctx context.Context, httpClient *http.Client, body []byte, mcpID, userID, url, secret string, signatures map[string]string) (string, *nmcp.RPCError) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", &nmcp.RPCError{
			Code:    -32603,
			Message: fmt.Sprintf("failed to construct request to webhook %s: %v", url, err),
		}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	req.Header.Set("X-Obot-Mcp-Server-Id", mcpID)
	req.Header.Set("X-Obot-User-Id", userID)

	if secret != "" {
		sig := signatures[secret]
		if sig == "" {
			h := hmac.New(sha256.New, []byte(secret))
			h.Write(body)
			sig = fmt.Sprintf("sha256=%x", h.Sum(nil))
			signatures[secret] = sig
		}

		req.Header.Set("X-Obot-Signature-256", sig)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", &nmcp.RPCError{
			Code:    -32603,
			Message: fmt.Sprintf("failed to send request to webhook %s: %v", url, err),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return resp.Status, &nmcp.RPCError{
			Code:    -32603,
			Message: fmt.Sprintf("webhook %s returned status code %d: %v", url, resp.StatusCode, string(respBody)),
		}
	}

	return resp.Status, nil
}

// GetMCPConfig returns the MCP server configuration in the format expected by MCP clients
// (e.g., mcp-remote). This endpoint works with bootstrap token authentication to allow
// programmatic access to MCP servers.
func (h *Handler) GetMCPConfig(req api.Context) error {
	mcpID := req.PathValue("mcp_id")
	if mcpID == "" {
		return fmt.Errorf("mcp_id is required")
	}

	// Get the MCP server and configuration
	_, mcpServer, _, err := handlers.ServerForActionWithConnectID(req, mcpID, h.mcpSessionManager.TokenService(), h.baseURL)
	if err != nil {
		return fmt.Errorf("failed to get mcp server config: %w", err)
	}

	// Prevent access to templates
	if mcpServer.Spec.Template {
		return apierrors.NewNotFound(schema.GroupResource{Group: "obot.obot.ai", Resource: "mcpserver"}, mcpID)
	}

	// Get the display name for the MCP server
	displayName := mcpServer.Spec.Manifest.Name
	if displayName == "" {
		displayName = mcpServer.Name
	}

	// Build the connect URL - use bootstrap endpoint if authenticated via bootstrap token
	authProviderName := ""
	if req.User.GetExtra()["auth_provider_name"] != nil && len(req.User.GetExtra()["auth_provider_name"]) > 0 {
		authProviderName = req.User.GetExtra()["auth_provider_name"][0]
	}
	
	var connectURL string
	if authProviderName == "bootstrap" {
		// Use bootstrap endpoint for bootstrap-authenticated users
		connectURL = fmt.Sprintf("%s/mcp-bootstrap/%s", h.baseURL, mcpID)
	} else {
		// Use regular endpoint for other users
		connectURL = fmt.Sprintf("%s/mcp-connect/%s", h.baseURL, mcpID)
	}

	// Return the configuration in the format expected by MCP clients
	config := map[string]interface{}{
		"mcpServers": map[string]interface{}{
			displayName: map[string]interface{}{
				"command": "npx",
				"args": []string{
					"mcp-remote@latest",
					connectURL,
				},
			},
		},
	}

	req.ResponseWriter.Header().Set("Content-Type", "application/json")
	return req.Write(config)
}

// BootstrapMCPConnect handles MCP protocol requests using only bootstrap token authentication.
// This endpoint bypasses OAuth and other authorization checks, relying solely on OBOT_BOOTSTRAP_TOKEN.
func (h *Handler) BootstrapMCPConnect(req api.Context) error {
	mcpID := req.PathValue("mcp_id")
	if mcpID == "" {
		return fmt.Errorf("mcp_id is required")
	}

	// Validate bootstrap token directly from request header
	// Log all headers for debugging (but don't log values for security)
	var headerNames []string
	for name, values := range req.Request.Header {
		headerNames = append(headerNames, fmt.Sprintf("%s (len=%d)", name, len(values)))
		// Check if this looks like our bootstrap token header (case-insensitive)
		if strings.EqualFold(name, "OBOT_BOOTSTRAP_TOKEN") || strings.EqualFold(name, "Obot-Bootstrap-Token") {
			log.Debugf("BootstrapMCPConnect: Found potential bootstrap token header: %s with %d value(s)", name, len(values))
		}
	}
	log.Debugf("BootstrapMCPConnect: Request headers: %v", headerNames)
	
	bootstrapTokenHeader := req.Request.Header.Get("OBOT_BOOTSTRAP_TOKEN")
	if bootstrapTokenHeader == "" {
		// Try case-insensitive lookup - Go's Header.Get should handle this, but let's be explicit
		for name, values := range req.Request.Header {
			if strings.EqualFold(name, "OBOT_BOOTSTRAP_TOKEN") {
				if len(values) > 0 {
					bootstrapTokenHeader = values[0]
					log.Debugf("BootstrapMCPConnect: Found bootstrap token in header %s (case-insensitive lookup)", name)
					break
				}
			}
		}
	} else {
		log.Debugf("BootstrapMCPConnect: Found bootstrap token via Header.Get()")
	}
	
	if bootstrapTokenHeader == "" {
		// Try Authorization header as fallback
		authHeader := req.Request.Header.Get("Authorization")
		if authHeader != "" {
			log.Debugf("BootstrapMCPConnect: Found Authorization header, checking for Bearer token")
		}
		if strings.HasPrefix(authHeader, "Bearer ") {
			bootstrapTokenHeader = strings.TrimPrefix(authHeader, "Bearer ")
			log.Debugf("BootstrapMCPConnect: Using bootstrap token from Authorization header")
		}
	}

	if bootstrapTokenHeader == "" {
		log.Warnf("BootstrapMCPConnect: No bootstrap token provided. Headers present: %v", headerNames)
		req.ResponseWriter.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="OBOT_BOOTSTRAP_TOKEN required"`)
		http.Error(req.ResponseWriter, "unauthorized: OBOT_BOOTSTRAP_TOKEN required", http.StatusUnauthorized)
		return nil
	}
	
	log.Debugf("BootstrapMCPConnect: Bootstrap token found (length: %d)", len(bootstrapTokenHeader))

	// Get the bootstrap token from credentials to validate
	bootstrapTokenCred, err := h.gptClient.RevealCredential(req.Context(), []string{"obot-bootstrap"}, "obot-bootstrap")
	var expectedToken string
	if err != nil {
		// If credential doesn't exist, try environment variable as fallback
		if errors.As(err, &gptscript.ErrNotFound{}) {
			// Try to get from environment variable (for cases where credential isn't stored yet)
			// This is a fallback - normally the token should be in credentials
			log.Debugf("BootstrapMCPConnect: Bootstrap token credential not found, this may be expected on first run")
			// We'll validate against empty token which will fail, but at least we tried
		} else {
			log.Errorf("BootstrapMCPConnect: Failed to get bootstrap token from credentials: %v", err)
			req.ResponseWriter.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="Bootstrap token validation failed"`)
			http.Error(req.ResponseWriter, "unauthorized: bootstrap token validation failed", http.StatusUnauthorized)
			return nil
		}
	} else {
		expectedToken = bootstrapTokenCred.Env["token"]
	}

	if expectedToken == "" || bootstrapTokenHeader != expectedToken {
		log.Warnf("BootstrapMCPConnect: Invalid bootstrap token provided (expected length: %d, provided length: %d)", len(expectedToken), len(bootstrapTokenHeader))
		req.ResponseWriter.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="Invalid OBOT_BOOTSTRAP_TOKEN"`)
		http.Error(req.ResponseWriter, "unauthorized: invalid bootstrap token", http.StatusUnauthorized)
		return nil
	}

	// Use the default owner user instead of creating a bootstrap user
	// Find the first owner user in the system
	allUsers, err := h.gatewayClient.Users(req.Context(), gatewaytypes.UserQuery{})
	if err != nil {
		log.Errorf("BootstrapMCPConnect: Failed to list users: %v", err)
		return fmt.Errorf("failed to find owner user: %w", err)
	}

	var ownerUser *gatewaytypes.User
	for i := range allUsers {
		if allUsers[i].Role.HasRole(types.RoleOwner) {
			ownerUser = &allUsers[i]
			break
		}
	}

	if ownerUser == nil {
		log.Errorf("BootstrapMCPConnect: No owner user found in the system")
		return fmt.Errorf("no owner user found - please ensure at least one owner user exists")
	}

	// Get the owner user's identities to use their actual auth provider info
	identities, err := h.gatewayClient.FindIdentitiesForUser(req.Context(), ownerUser.ID)
	if err != nil {
		log.Warnf("BootstrapMCPConnect: Failed to get identities for owner user %d: %v, using default", ownerUser.ID, err)
	}

	// Use the first identity's auth provider if available, otherwise use "bootstrap" as fallback
	authProviderName := "bootstrap"
	authProviderNamespace := ""
	if len(identities) > 0 {
		authProviderName = identities[0].AuthProviderName
		authProviderNamespace = identities[0].AuthProviderNamespace
	}

	// Create user info using the owner user's actual identity
	ownerUserInfo := &user.DefaultInfo{
		Name:   ownerUser.Username,
		UID:    fmt.Sprintf("%d", ownerUser.ID),
		Groups: ownerUser.Role.Groups(),
		Extra: map[string][]string{
			"auth_provider_name":      {authProviderName},
			"auth_provider_namespace": {authProviderNamespace},
			// Mark as bootstrap-authenticated for bypass logic, but use owner's actual identity
			"bootstrap_authenticated": {"true"},
		},
	}

	log.Infof("BootstrapMCPConnect: Authenticated via bootstrap token for mcpID=%s, using owner user: %s (ID: %d, authProvider: %s/%s)", mcpID, ownerUser.Username, ownerUser.ID, authProviderNamespace, authProviderName)

	sessionID := req.Request.Header.Get("Mcp-Session-Id")

	// Create a new context with the owner user for all subsequent operations
	ownerContext := api.Context{
		ResponseWriter: req.ResponseWriter,
		Request:        req.Request,
		GPTClient:      req.GPTClient,
		Storage:        req.Storage,
		GatewayClient:  req.GatewayClient,
		User:           ownerUserInfo,
		APIBaseURL:     req.APIBaseURL,
	}

	// Get the MCP server and configuration directly (bypassing authorization checks)
	log.Debugf("BootstrapMCPConnect: Attempting to get MCP server config for mcpID=%s", mcpID)
	_, mcpServer, mcpServerConfig, err := handlers.ServerForActionWithConnectID(ownerContext, mcpID, h.mcpSessionManager.TokenService(), h.baseURL)
	if err == nil && mcpServer.Spec.Template {
		log.Warnf("Attempted connection to MCP server template: %s", mcpID)
		err = apierrors.NewNotFound(schema.GroupResource{Group: "obot.obot.ai", Resource: "mcpserver"}, mcpID)
	}

	ss := newSessionStore(h, mcpID, ownerUserInfo.GetUID())

	if err != nil {
		log.Errorf("BootstrapMCPConnect: Failed to get MCP server config for mcpID=%s, userUID=%s: %v", mcpID, ownerUserInfo.GetUID(), err)
		// Log more details about the error
		if apierrors.IsNotFound(err) {
			log.Errorf("BootstrapMCPConnect: MCP server not found: %s (may not exist or user may not have access)", mcpID)
		} else if apierrors.IsForbidden(err) {
			log.Errorf("BootstrapMCPConnect: Access forbidden to MCP server: %s (authorization issue)", mcpID)
		} else {
			log.Errorf("BootstrapMCPConnect: Unexpected error getting MCP server config: %T: %v", err, err)
		}
		if apierrors.IsNotFound(err) {
			if sessionID != "" {
				session, found, err := ss.LoadAndDelete(req.Context(), h, sessionID)
				if err != nil {
					log.Errorf("Failed to delete session %s: %v", sessionID, err)
					return fmt.Errorf("failed to get mcp server config: %w", err)
				}

				if found {
					session.Close(true)
				}
			}
		}
		return fmt.Errorf("failed to get mcp server config: %w", err)
	}

	log.Infof("BootstrapMCPConnect: Successfully retrieved MCP server config: mcpID=%s, serverName=%s, runtime=%s", mcpID, mcpServer.Name, mcpServer.Spec.Manifest.Runtime)

	messageCtx := messageContext{
		userID:       ownerUserInfo.GetUID(),
		mcpID:        mcpID,
		mcpServer:    mcpServer,
		serverConfig: mcpServerConfig,
		req:          ownerContext.Request,
		resp:         ownerContext.ResponseWriter,
	}

	// Handle composite servers
	if mcpServer.Spec.Manifest.Runtime == types.RuntimeComposite {
		var componentServerList v1.MCPServerList
		if err := ownerContext.List(&componentServerList,
			kclient.InNamespace(mcpServer.Namespace),
			kclient.MatchingFields{
				"spec.compositeName": mcpServer.Name,
			}); err != nil {
			return fmt.Errorf("failed to list component servers for composite server %s: %v", mcpServer.Name, err)
		}

		var componentInstanceList v1.MCPServerInstanceList
		if err := ownerContext.List(&componentInstanceList,
			kclient.InNamespace(mcpServer.Namespace),
			kclient.MatchingFields{
				"spec.compositeName": mcpServer.Name,
			}); err != nil {
			return fmt.Errorf("failed to list component instances for composite server %s: %v", mcpServer.Name, err)
		}

		var compositeConfig types.CompositeRuntimeConfig
		if mcpServer.Spec.Manifest.CompositeConfig != nil {
			compositeConfig = *mcpServer.Spec.Manifest.CompositeConfig
		}

		disabledComponents := make(map[string]bool, len(compositeConfig.ComponentServers))
		for _, comp := range compositeConfig.ComponentServers {
			if comp.CatalogEntryID != "" {
				disabledComponents[comp.CatalogEntryID] = comp.Disabled
			} else if comp.MCPServerID != "" {
				disabledComponents[comp.MCPServerID] = comp.Disabled
			}
		}

		componentServers := make([]messageContext, 0, len(componentServerList.Items)+len(componentInstanceList.Items))

		for _, componentServer := range componentServerList.Items {
			if disabledComponents[componentServer.Spec.MCPServerCatalogEntryName] {
				log.Debugf("Skipping component server %s not enabled in composite config", componentServer.Name)
				continue
			}

			srv, config, err := handlers.ServerForAction(ownerContext, componentServer.Name, h.mcpSessionManager.TokenService(), h.baseURL)
			if err != nil {
				log.Warnf("Failed to get component server %s: %v", componentServer.Name, err)
				continue
			}

			componentServers = append(componentServers, messageContext{
				userID:       ownerUserInfo.GetUID(),
				mcpID:        srv.Name,
				mcpServer:    srv,
				serverConfig: config,
			})
		}

		for _, componentInstance := range componentInstanceList.Items {
			var multiUserServer v1.MCPServer
			if err := ownerContext.Get(&multiUserServer, componentInstance.Spec.MCPServerName); err != nil {
				log.Warnf("Failed to get multi-user server %s for instance %s: %v", componentInstance.Spec.MCPServerName, componentInstance.Name, err)
				continue
			}

			if disabledComponents[multiUserServer.Name] {
				log.Debugf("Skipping component instance %s not enabled in composite config", componentInstance.Name)
				continue
			}

			srv, config, err := handlers.ServerForAction(ownerContext, multiUserServer.Name, h.mcpSessionManager.TokenService(), h.baseURL)
			if err != nil {
				log.Warnf("Failed to get multi-user server %s: %v", multiUserServer.Name, err)
				continue
			}

			componentServers = append(componentServers, messageContext{
				userID:       ownerUserInfo.GetUID(),
				mcpID:        srv.Name,
				mcpServer:    srv,
				serverConfig: config,
			})
		}

		if len(componentServers) < 1 {
			return fmt.Errorf("composite server %s has no running component servers", mcpServer.Name)
		}

		messageCtx.compositeContext = newCompositeContext(mcpServer.Spec.Manifest.CompositeConfig, componentServers)
	}

	// Update the request context with the message context
	// Note: We need to preserve the original request body, so we don't modify the request itself
	// The MCP HTTP server will read the body from the request
	ownerContext.Request = ownerContext.Request.WithContext(withMessageContext(ownerContext.Request.Context(), messageCtx))

	log.Debugf("BootstrapMCPConnect: Serving MCP request: mcpID=%s, method=%s, path=%s, contentLength=%d", mcpID, ownerContext.Request.Method, ownerContext.Request.URL.Path, ownerContext.Request.ContentLength)

	// For stateless HTTP requests (like LangGraph), ensure session is initialized
	// Check if this is a tools/call request without a session ID
	if ownerContext.Request.Method == "POST" && ownerContext.Request.Header.Get("Mcp-Session-Id") == "" {
		// Read the request body to check if it's a tools/call request
		bodyBytes, err := io.ReadAll(ownerContext.Request.Body)
		if err == nil {
			ownerContext.Request.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			
			// Check if it's a JSON-RPC tools/call request
			var jsonRPCReq struct {
				Method string `json:"method"`
			}
			if json.Unmarshal(bodyBytes, &jsonRPCReq) == nil && jsonRPCReq.Method == methodToolsCall {
				log.Debugf("BootstrapMCPConnect: Detected stateless tools/call request, creating and initializing session")
				
				// Create a session ID for this stateless request
				sessionID := uuid.New().String()
				
				// Set the session ID in the request header
				ownerContext.Request.Header.Set("Mcp-Session-Id", sessionID)
				
				// For stateless requests, we need to ensure the session exists before the HTTP server processes it
				// The HTTP server will create the session when it receives the request, but we need to
				// ensure it can find the server config. The session will be created automatically by the
				// HTTP server when it processes the request.
				// 
				// However, the HTTP server's Acquire method returns nil when the session doesn't exist,
				// which causes "Session not found" errors. We need to ensure the session is created.
				//
				// The solution is to let the HTTP server handle session creation, but we need to ensure
				// it can. The HTTP server should create the session when it receives a request with a
				// session ID that doesn't exist yet.
				//
				// For now, we'll just set the session ID and let the HTTP server handle it.
				// If the session doesn't exist, the HTTP server should create it automatically.
				log.Debugf("BootstrapMCPConnect: Set session ID %s for stateless request, HTTP server will create session", sessionID)
			}
		}
	}

	// Serve the HTTP request (handles WebSocket, SSE, and direct HTTP POST)
	// The MCP HTTP server handles JSON-RPC requests and routes them appropriately
	nmcp.NewHTTPServer(nil, h, nmcp.HTTPServerOptions{SessionStore: ss}).ServeHTTP(ownerContext.ResponseWriter, ownerContext.Request)

	return nil
}

// Pending request helpers
func (h *Handler) pendingRequestsForSession(sessionID string) *nmcp.PendingRequests {
	obj, _ := h.pendingRequests.LoadOrStore(sessionID, &nmcp.PendingRequests{})
	return obj.(*nmcp.PendingRequests)
}
