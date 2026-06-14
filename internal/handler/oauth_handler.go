package handler

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/open-stash/sentinel/internal/service"
)

type OAuthHandler struct {
	svc *service.OAuthService
}

func NewOAuthHandler(svc *service.OAuthService) *OAuthHandler {
	return &OAuthHandler{svc: svc}
}

// Metadata serves /.well-known/oauth-authorization-server (RFC 8414).
func (h *OAuthHandler) Metadata(c *gin.Context) {
	c.JSON(http.StatusOK, h.svc.Metadata())
}

// JWKS serves /.well-known/jwks.json — public keys for token verification.
func (h *OAuthHandler) JWKS(c *gin.Context) {
	c.JSON(http.StatusOK, h.svc.JWKS())
}

type registerClientRequest struct {
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
}

// Register is Dynamic Client Registration (RFC 7591). Public — ChatGPT/Claude self-register.
// We decode manually (encoding/json ignores unknown fields) because the global gin decoder
// is set to reject unknown fields — but DCR payloads carry many fields we don't use
// (grant_types, response_types, token_endpoint_auth_method, scope, …).
func (h *OAuthHandler) Register(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client_metadata"})
		return
	}
	var req registerClientRequest
	if err := json.Unmarshal(body, &req); err != nil || len(req.RedirectURIs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client_metadata"})
		return
	}
	client, err := h.svc.RegisterClient(c.Request.Context(), req.ClientName, req.RedirectURIs)
	if err != nil {
		slog.Error("oauth register", "error", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client_metadata"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{
		"client_id":                  client.ClientID,
		"client_id_issued_at":        time.Now().Unix(),
		"client_name":                client.ClientName,
		"redirect_uris":              client.RedirectURIs,
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
}

type issueCodeRequest struct {
	ClientID      string `json:"client_id" binding:"required"`
	RedirectURI   string `json:"redirect_uri" binding:"required"`
	CodeChallenge string `json:"code_challenge" binding:"required"`
	Scope         string `json:"scope"`
	Resource      string `json:"resource"`
}

// IssueCode is called server-side by the holonet consent page after the user approves.
// It is behind the auth middleware: the user_id comes from the session, not the body.
func (h *OAuthHandler) IssueCode(c *gin.Context) {
	claims := claimsFromCtx(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, errResp("unauthorized"))
		return
	}
	var req issueCodeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp("invalid request"))
		return
	}
	code, err := h.svc.IssueCode(
		c.Request.Context(), claims.Subject, req.ClientID, req.RedirectURI,
		req.CodeChallenge, req.Scope, req.Resource,
	)
	if err != nil {
		c.JSON(http.StatusBadRequest, errResp("could not authorize client"))
		return
	}
	c.JSON(http.StatusOK, ok("", gin.H{"code": code}))
}

// Token is the OAuth token endpoint (form-encoded, per spec). Public — PKCE is the proof.
func (h *OAuthHandler) Token(c *gin.Context) {
	grant := c.PostForm("grant_type")
	var (
		res *service.TokenResult
		err error
	)
	switch grant {
	case "authorization_code":
		res, err = h.svc.ExchangeCode(
			c.Request.Context(),
			c.PostForm("code"), c.PostForm("code_verifier"),
			c.PostForm("redirect_uri"), c.PostForm("client_id"),
		)
	case "refresh_token":
		res, err = h.svc.Refresh(c.Request.Context(), c.PostForm("refresh_token"), c.PostForm("client_id"))
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
		return
	}
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": oauthErrorCode(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"access_token":  res.AccessToken,
		"token_type":    "Bearer",
		"expires_in":    res.ExpiresIn,
		"refresh_token": res.RefreshToken,
		"scope":         res.Scope,
	})
}

// ListConnections returns the apps the user has connected to their memory (authed).
func (h *OAuthHandler) ListConnections(c *gin.Context) {
	claims := claimsFromCtx(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, errResp("unauthorized"))
		return
	}
	conns, err := h.svc.ListConnections(c.Request.Context(), claims.Subject)
	if err != nil {
		slog.Error("list oauth connections", "error", err, "userID", claims.Subject)
		c.JSON(http.StatusInternalServerError, errResp("could not load connected apps"))
		return
	}
	out := make([]gin.H, 0, len(conns))
	for _, cn := range conns {
		out = append(out, gin.H{
			"client_id": cn.ClientID, "name": cn.Name,
			"connected_at": cn.ConnectedAt, "last_active_at": cn.LastActiveAt,
		})
	}
	c.JSON(http.StatusOK, ok("", gin.H{"connections": out}))
}

// RevokeConnection disconnects an app (authed).
func (h *OAuthHandler) RevokeConnection(c *gin.Context) {
	claims := claimsFromCtx(c)
	if claims == nil {
		c.JSON(http.StatusUnauthorized, errResp("unauthorized"))
		return
	}
	if err := h.svc.RevokeConnection(c.Request.Context(), claims.Subject, c.Param("client_id")); err != nil {
		slog.Error("revoke oauth connection", "error", err, "userID", claims.Subject)
		c.JSON(http.StatusInternalServerError, errResp("could not disconnect app"))
		return
	}
	c.JSON(http.StatusOK, ok("App disconnected", nil))
}

func oauthErrorCode(err error) string {
	switch {
	case errors.Is(err, service.ErrOAuthInvalidClient):
		return "invalid_client"
	case errors.Is(err, service.ErrOAuthInvalidRequest), errors.Is(err, service.ErrOAuthInvalidRedirect):
		return "invalid_request"
	default:
		return "invalid_grant"
	}
}
