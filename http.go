package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap/zapcore"

	"github.com/hashicorp/nomad/helper/uuid"

	jwt "github.com/dgrijalva/jwt-go"
	"go.uber.org/zap"
)

const (
	CtxLoggerKey = "logger"
	CtxJWTKey    = "jwt"
)

type Server struct {
	store *TokenStore
	l     *zap.Logger
}

func (s *Server) LoggerForReq(r *http.Request) *zap.Logger {
	if l, ok := r.Context().Value(CtxLoggerKey).(*zap.Logger); ok {
		return l
	}
	return s.l
}

func enrichLoggerForReq(r *http.Request, fs ...zapcore.Field) (*zap.Logger, *http.Request) {
	var logger *zap.Logger
	l, ok := r.Context().Value(CtxLoggerKey).(*zap.Logger)
	if !ok {
		logger = zap.NewNop()
	} else {
		logger = l.With(fs...)
	}
	return logger, r.WithContext(context.WithValue(r.Context(), CtxLoggerKey, logger))

}

func (s *Server) LoggerInit(h http.Handler) http.HandlerFunc {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), CtxLoggerKey, s.l.With(
				zap.String("remote-addr", r.RemoteAddr),
				zap.String("uuid", uuid.Generate()),
			))

			h.ServeHTTP(w, r.WithContext(ctx))
		})
}

func sendErr(l *zap.Logger, w http.ResponseWriter, code int, msg string) {
	l.Error(msg)
	if code < 400 {
		code = 500
	}
	w.WriteHeader(code)
	w.Write([]byte(msg))
}

func (s *Server) VaultTokenAssign(h http.Handler) http.HandlerFunc {
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			l := s.LoggerForReq(r)

			tok, err := s.store.GetToken(r.Context().Value(CtxJWTKey).(*jwt.Token))
			if err != nil {
				sendErr(l, w, 403, fmt.Sprintf("error: %s", err.Error()))
				return
			}
			if tok == nil {
				sendErr(l, w, 500, "unknown error when getting vault token from JWT")
				return
			}

			r.Header.Set("X-Vault-Token", tok.Value)
			l.Debug("success", zap.String("url", r.URL.RequestURI()))
			h.ServeHTTP(w, r)
			if !s.store.cacheEnabled {
				tok.Cancel()
			}
		})
}

func (s *Server) JWTExtract(h http.Handler) http.HandlerFunc {
	jwtParser := jwt.Parser{}
	return http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			l := s.LoggerForReq(r)
			var JWT *jwt.Token
			JWTClaims := jwt.MapClaims{}
			if *devMode {
				JWTClaims = jwt.MapClaims{
					"iss": "debug-issuer",
					"iat": time.Now().Unix(),
					"exp": time.Now().Add(10 * time.Hour).Unix(),
					"sub": "debug-subject",
				}
				JWT = jwt.NewWithClaims(jwt.SigningMethodRS384, JWTClaims)
			}
			// Try Authorization Header
			if authHeader := r.Header.Get("Authorization"); authHeader != "" {
				l := l.With(zap.String("auth-header", authHeader))
				l.Debug("header found")
				if !strings.HasPrefix(authHeader, "Bearer ") {
					sendErr(l, w, 400, "invalid authorization header format. Please follow RFC-6750")
					return
				}
				tok, _, err := jwtParser.ParseUnverified(authHeader[7:], JWTClaims)
				if err != nil {
					sendErr(l.With(zap.Error(err)), w, 400, "invalid jwt given")
					return
				}
				r.Header.Del("Authorization")
				JWT = tok
			}
			if JWT == nil {
				// Try Cookie
				if c, _ := r.Cookie("vault_jwt_proxy_auth"); c != nil && c.Value != "" {
					l := l.With(zap.String("cookie", c.Value))
					l.Debug("cookie found")
					// We don't care about verifying the tokens
					tok, _, err := jwtParser.ParseUnverified(c.Value, JWTClaims)
					if err != nil {
						sendErr(l.With(zap.Error(err)), w, 400, "invalid jwt given")
						return
					}
					JWT = tok
				}
			}
			if JWT == nil {
				sendErr(l, w, 400, "can't find jwt in either 'vault_jwt_proxy_auth' or 'Authorization' Bearer")
				return
			}
			if err := JWT.Claims.Valid(); err != nil {
				sendErr(l, w, 403, fmt.Sprintf("invalid jwt: %s", err.Error()))
				return
			}
			_, r = enrichLoggerForReq(r,
				zap.String("issuer", JWTClaims["iss"].(string)),
				zap.String("subject", JWTClaims["sub"].(string)),
				zap.Time("issue-time", time.Unix(int64(JWTClaims["iat"].(float64)), 0)),
				zap.Time("expiration-time", time.Unix(int64(JWTClaims["exp"].(float64)), 0)),
			)
			if *cookieMode {
				http.SetCookie(w, &http.Cookie{Name: "vault_jwt_proxy_auth", Value: JWT.Raw})
			}
			h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), CtxJWTKey, JWT)))
		})
}
