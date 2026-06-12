package handler

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/open-stash/sentinel/internal/service"
	jwtpkg "github.com/open-stash/sentinel/pkg/jwt"
	"github.com/open-stash/sentinel/pkg/password"
)

type AuthHandler struct {
	svc *service.AuthService
}

const (
	refreshCookieName    = "refresh_token"
	refreshCookiePath    = "/api/v1/auth"
	refreshCookieMaxAgeS = 7 * 24 * 60 * 60
)

func NewAuthHandler(svc *service.AuthService) *AuthHandler {
	return &AuthHandler{svc: svc}
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

func (h *AuthHandler) Register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp(err.Error()))
		return
	}

	user, err := h.svc.Register(c.Request.Context(), req.Name, req.Email, req.Password)
	if err != nil {
		handleServiceErr(c, err)
		return
	}

	c.JSON(http.StatusCreated, ok("registered successfully, verify your email to activate your account", gin.H{
		"user_id": user.ID,
		"email":   user.Email,
	}))
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp(err.Error()))
		return
	}

	out, err := h.svc.Login(c.Request.Context(), service.LoginInput{
		Email:     req.Email,
		Password:  req.Password,
		TOTPCode:  req.TOTPCode,
		UserAgent: c.Request.UserAgent(),
	})
	if err != nil {
		if errors.Is(err, service.ErrTOTPRequired) {
			c.JSON(http.StatusOK, gin.H{"status": "totp_required"})
			return
		}
		handleServiceErr(c, err)
		return
	}

	h.setRefreshCookie(c, out.Tokens.RefreshToken)
	c.JSON(http.StatusOK, ok("login successful", gin.H{
		"access_token": out.Tokens.AccessToken,
		"user": gin.H{
			"id":    out.User.ID,
			"email": out.User.Email,
			"role":  out.User.Role,
		},
	}))
}

func (h *AuthHandler) Logout(c *gin.Context) {
	claims := claimsFromCtx(c)
	refreshToken, _ := h.refreshTokenFromCookie(c)

	rawToken := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")

	if err := h.svc.Logout(c.Request.Context(), rawToken, refreshToken, claims.Subject); err != nil {
		slog.Error("logout", "error", err, "userID", claims.Subject)
	}
	h.clearRefreshCookie(c)

	c.JSON(http.StatusOK, ok("logged out", nil))
}

func (h *AuthHandler) Refresh(c *gin.Context) {
	refreshToken, err := h.refreshTokenFromCookie(c)
	if err != nil {
		c.JSON(http.StatusUnauthorized, errResp("refresh token cookie is missing"))
		return
	}

	pair, err := h.svc.Refresh(c.Request.Context(), service.RefreshInput{
		RefreshToken: refreshToken,
		UserAgent:    c.Request.UserAgent(),
	})
	if err != nil {
		handleServiceErr(c, err)
		return
	}
	h.setRefreshCookie(c, pair.RefreshToken)
	c.JSON(http.StatusOK, ok("token refreshed", gin.H{
		"access_token": pair.AccessToken,
	}))
}

func (h *AuthHandler) VerifyEmail(c *gin.Context) {
	var q verifyEmailQuery
	if err := c.ShouldBindQuery(&q); err != nil {
		c.JSON(http.StatusBadRequest, errResp(err.Error()))
		return
	}

	if err := h.svc.VerifyEmail(c.Request.Context(), q.Token); err != nil {
		handleServiceErr(c, err)
		return
	}

	c.JSON(http.StatusOK, ok("email verified successfully", nil))
}

func (h *AuthHandler) ForgotPassword(c *gin.Context) {
	var req forgotPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp(err.Error()))
		return
	}

	token, err := h.svc.ForgotPassword(c.Request.Context(), req.Email)
	if err != nil {
		slog.Error("forgot password", "error", err)
		c.JSON(http.StatusInternalServerError, errResp("internal server error"))
		return
	}

	// Always respond 200 — never reveal whether email exists
	resp := gin.H{"message": "if that email is registered, you will receive a reset link"}
	if token != "" {
		// TODO: remove once email sending is implemented
		resp["reset_token"] = token
	}
	c.JSON(http.StatusOK, ok("", resp))
}

func (h *AuthHandler) ResetPassword(c *gin.Context) {
	var req resetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp(err.Error()))
		return
	}

	if err := h.svc.ResetPassword(c.Request.Context(), req.Token, req.NewPassword); err != nil {
		handleServiceErr(c, err)
		return
	}

	c.JSON(http.StatusOK, ok("password reset successfully", nil))
}

func (h *AuthHandler) SetupTOTP(c *gin.Context) {
	claims := claimsFromCtx(c)

	out, err := h.svc.SetupTOTP(c.Request.Context(), claims.Subject)
	if err != nil {
		handleServiceErr(c, err)
		return
	}

	c.JSON(http.StatusOK, ok("scan the QR code with your authenticator app, then call /totp/enable", gin.H{
		"secret":       out.Secret,
		"otp_auth_url": out.OTPAuthURL,
	}))
}

func (h *AuthHandler) EnableTOTP(c *gin.Context) {
	var req enableTOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, errResp(err.Error()))
		return
	}

	claims := claimsFromCtx(c)

	if err := h.svc.EnableTOTP(c.Request.Context(), claims.Subject, req.Code); err != nil {
		handleServiceErr(c, err)
		return
	}

	c.JSON(http.StatusOK, ok("2FA enabled", nil))
}

// Introspect lets other services (kyber, holocron) validate an access token
// against live session state. Send the token as Bearer; returns {active, ...}.
// Always 200 — an invalid token is just {"active": false}.
func (h *AuthHandler) Introspect(c *gin.Context) {
	token := strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	res := h.svc.Introspect(c.Request.Context(), token)
	if !res.Active {
		c.JSON(http.StatusOK, gin.H{"active": false})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"active": true,
		"sub":    res.UserID,
		"email":  res.Email,
		"role":   res.Role,
		"sid":    res.SID,
	})
}

// ─── session management ────────────────────────────────────────────────────────

func (h *AuthHandler) ListSessions(c *gin.Context) {
	claims := claimsFromCtx(c)
	sessions, err := h.svc.ListSessions(c.Request.Context(), claims.Subject)
	if err != nil {
		slog.Error("list sessions", "error", err, "userID", claims.Subject)
		c.JSON(http.StatusInternalServerError, errResp("could not load sessions"))
		return
	}

	out := make([]gin.H, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, gin.H{
			"id":         s.ID,
			"current":    s.ID == claims.SID,
			"device":     s.Device,
			"browser":    s.Browser,
			"os":         s.OS,
			"created_at": s.CreatedAt,
			"last_seen":  s.LastSeenAt,
		})
	}
	c.JSON(http.StatusOK, ok("", gin.H{"sessions": out}))
}

func (h *AuthHandler) RevokeSession(c *gin.Context) {
	claims := claimsFromCtx(c)
	id := c.Param("id")
	if err := h.svc.RevokeSession(c.Request.Context(), id, claims.Subject); err != nil {
		slog.Error("revoke session", "error", err, "userID", claims.Subject, "sessionID", id)
		c.JSON(http.StatusInternalServerError, errResp("could not revoke session"))
		return
	}
	c.JSON(http.StatusOK, ok("session revoked", nil))
}

func (h *AuthHandler) RevokeOtherSessions(c *gin.Context) {
	claims := claimsFromCtx(c)
	if err := h.svc.RevokeOtherSessions(c.Request.Context(), claims.Subject, claims.SID); err != nil {
		slog.Error("revoke other sessions", "error", err, "userID", claims.Subject)
		c.JSON(http.StatusInternalServerError, errResp("could not revoke sessions"))
		return
	}
	c.JSON(http.StatusOK, ok("signed out of other devices", nil))
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func claimsFromCtx(c *gin.Context) *jwtpkg.Claims {
	v, _ := c.Get("claims")
	claims, _ := v.(*jwtpkg.Claims)
	return claims
}

func (h *AuthHandler) setRefreshCookie(c *gin.Context, refreshToken string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     refreshCookieName,
		Value:    refreshToken,
		Path:     refreshCookiePath,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   refreshCookieMaxAgeS,
		Expires:  time.Now().Add(time.Duration(refreshCookieMaxAgeS) * time.Second),
	})
}

func (h *AuthHandler) clearRefreshCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     refreshCookiePath,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
	})
}

func (h *AuthHandler) refreshTokenFromCookie(c *gin.Context) (string, error) {
	refreshToken, err := c.Cookie(refreshCookieName)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(refreshToken) == "" {
		return "", errors.New("refresh token cookie is empty")
	}
	return refreshToken, nil
}

func handleServiceErr(c *gin.Context, err error) {
	var rateLimitErr *service.RateLimitedError
	if errors.As(err, &rateLimitErr) {
		c.Header("Retry-After", fmt.Sprintf("%d", int(rateLimitErr.RetryAfter.Seconds())))
		c.JSON(http.StatusTooManyRequests, errResp(rateLimitErr.Error()))
		return
	}

	switch {
	case errors.Is(err, service.ErrEmailTaken):
		c.JSON(http.StatusConflict, errResp("email already registered"))
	case errors.Is(err, service.ErrInvalidCredentials):
		c.JSON(http.StatusUnauthorized, errResp("invalid email or password"))
	case errors.Is(err, service.ErrAccountLocked):
		c.JSON(http.StatusTooManyRequests, errResp("account temporarily locked due to too many failed attempts"))
	case errors.Is(err, service.ErrEmailNotVerified):
		c.JSON(http.StatusForbidden, errResp("verify your email address before logging in"))
	case errors.Is(err, service.ErrInvalid2FA):
		c.JSON(http.StatusUnauthorized, errResp("invalid 2FA code"))
	case errors.Is(err, service.ErrInvalidToken):
		c.JSON(http.StatusUnauthorized, errResp("invalid or expired token"))
	case errors.Is(err, service.ErrTOTPAlreadyEnabled):
		c.JSON(http.StatusConflict, errResp("2FA is already enabled on this account"))
	case errors.Is(err, service.ErrTOTPNotSetup):
		c.JSON(http.StatusBadRequest, errResp("call /totp/setup first to generate a secret"))
	case errors.Is(err, password.ErrTooShort),
		errors.Is(err, password.ErrMissingUppercase),
		errors.Is(err, password.ErrMissingDigit):
		c.JSON(http.StatusBadRequest, errResp(err.Error()))
	default:
		slog.Error("unhandled service error", "error", err)
		c.JSON(http.StatusInternalServerError, errResp("internal server error"))
	}
}
