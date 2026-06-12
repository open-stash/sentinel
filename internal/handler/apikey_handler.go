package handler

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/open-stash/sentinel/internal/repository"
	"github.com/open-stash/sentinel/internal/service"
)

type APIKeyHandler struct {
	svc *service.APIKeyService
}

func NewAPIKeyHandler(svc *service.APIKeyService) *APIKeyHandler {
	return &APIKeyHandler{svc: svc}
}

type createAPIKeyRequest struct {
	Name string `json:"name"`
}

type verifyAPIKeyRequest struct {
	Key string `json:"key" binding:"required"`
}

// Create mints a key and returns the plaintext ONCE.
func (h *APIKeyHandler) Create(c *gin.Context) {
	claims := claimsFromCtx(c)
	var req createAPIKeyRequest
	_ = c.ShouldBindJSON(&req)

	raw, key, err := h.svc.Create(c.Request.Context(), claims.Subject, req.Name)
	if err != nil {
		slog.Error("create api key", "error", err, "userID", claims.Subject)
		c.JSON(http.StatusInternalServerError, errResp("could not create API key"))
		return
	}
	c.JSON(http.StatusCreated, ok("API key created — copy it now, it won't be shown again", gin.H{
		"id":         key.ID,
		"name":       key.Name,
		"prefix":     key.Prefix,
		"key":        raw, // shown once
		"created_at": key.CreatedAt,
	}))
}

func (h *APIKeyHandler) List(c *gin.Context) {
	claims := claimsFromCtx(c)
	keys, err := h.svc.List(c.Request.Context(), claims.Subject)
	if err != nil {
		slog.Error("list api keys", "error", err, "userID", claims.Subject)
		c.JSON(http.StatusInternalServerError, errResp("could not load API keys"))
		return
	}
	out := make([]gin.H, 0, len(keys))
	for _, k := range keys {
		out = append(out, gin.H{
			"id":           k.ID,
			"name":         k.Name,
			"prefix":       k.Prefix,
			"last_used_at": k.LastUsedAt,
			"created_at":   k.CreatedAt,
		})
	}
	c.JSON(http.StatusOK, ok("", gin.H{"keys": out}))
}

func (h *APIKeyHandler) Revoke(c *gin.Context) {
	claims := claimsFromCtx(c)
	id := c.Param("id")
	if err := h.svc.Revoke(c.Request.Context(), id, claims.Subject); err != nil {
		slog.Error("revoke api key", "error", err, "userID", claims.Subject, "keyID", id)
		c.JSON(http.StatusInternalServerError, errResp("could not revoke API key"))
		return
	}
	c.JSON(http.StatusOK, ok("API key revoked", nil))
}

// Verify is the service-to-service endpoint holocron calls to resolve a presented
// key to its owner. Unauthenticated (the key itself is the credential).
func (h *APIKeyHandler) Verify(c *gin.Context) {
	var req verifyAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"active": false})
		return
	}
	userID, err := h.svc.Verify(c.Request.Context(), req.Key)
	if err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			c.JSON(http.StatusOK, gin.H{"active": false})
			return
		}
		slog.Error("verify api key", "error", err)
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{"active": true, "user_id": userID})
}
