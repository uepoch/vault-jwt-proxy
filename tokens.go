package main

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"net/url"
	"time"

	"go.uber.org/zap"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/golang-lru"
	"github.com/hashicorp/vault/api"
)

type RoleAssignator interface {
	RoleFromClaims(claims jwt.MapClaims) string
}

type RoleStatic string

func (r RoleStatic) RoleFromClaims(_ jwt.MapClaims) string {
	return string(r)
}

type RoleMap map[string]string

func (r RoleMap) RoleFromClaims(m jwt.MapClaims) string {
	var ok bool
	for r, v := range r {
		if _, ok = m[r]; ok {
			return v
		}
	}
	return ""
}

type Token struct {
	Client          *api.Client
	HashKey         string
	Value           string
	Period          time.Duration
	Refresher       *time.Ticker
	LastRefreshTime time.Time
	ctx             context.Context
}

func (ts *TokenStore) NewToken(value string) (*Token, error) {
	var l zap.Field
	if ts.l.Core().Enabled(zap.DebugLevel) {
		l = zap.String("token", value)
	} else {
		l = zap.String("token-prefix", value[:8])
	}
	ctx := context.WithValue(context.Background(), CtxLoggerKey, ts.l.With(l))
	client, err := ts.Client.Clone()
	if err != nil {
		return nil, err
	}
	client.SetToken(value)
	s, err := client.Auth().Token().LookupSelf()
	if err != nil {
		return nil, err
	}
	ttlRaw, ok := s.Data["ttl"].(json.Number)
	if !ok {
		return nil, fmt.Errorf("error while converting ttl from token")
	}
	ttl, err := ttlRaw.Int64()
	if err != nil {
		return nil, fmt.Errorf("error while extracting ttl from token: %s", err.Error())
	}
	t := &Token{Value: value, Refresher: time.NewTicker(time.Duration(ttl/2) * time.Second), Client: client, ctx: ctx}
	t.Bootstrap(ts.cacheEnabled)
	return t, nil
}

func (t *Token) Logger() *zap.Logger {
	if l, ok := t.ctx.Value(CtxLoggerKey).(*zap.Logger); ok {
		return l
	}
	return zap.NewNop()
}

func (t *Token) Bootstrap(enableRefresh bool) {
	l := t.Logger()

	if enableRefresh {
		go func() {
			for range t.Refresher.C {
				t.Refresh()
			}
		}()
	}
	l.Debug("token boostrapped")
}

func (t *Token) Refresh() {
	_, err := t.Client.Auth().Token().RenewSelf(0)
	if err != nil {
	}
	t.LastRefreshTime = time.Now()
	t.Logger().Info("token refreshed", zap.Time("refresh-time", t.LastRefreshTime))
}

func (t *Token) Cancel() {
	t.Client.Auth().Token().RevokeSelf(t.Value)
	t.Logger().Debug("token cancelled")
}

type TokenStore struct {
	Cache        *lru.Cache
	Client       *api.Client
	cacheEnabled bool
	l            *zap.Logger
	rs           RoleAssignator
}

func NewTokenStore(size int, logger *zap.Logger, vaultAddr *url.URL, rs RoleAssignator) (*TokenStore, error) {
	ts := &TokenStore{}

	ts.l = logger
	ts.rs = rs

	conf := api.DefaultConfig()
	conf.Address = vaultAddr.String()
	client, err := api.NewClient(conf)
	if err != nil {
		return nil, err
	}
	ts.Client = client
	if size < 0 {
		return nil, fmt.Errorf("you have to pass a positive value in size for NewTokenStore")
	}
	if size == 0 {
		ts.l.Info("Token caching disabled")
		ts.cacheEnabled = false
	} else {
		cache, err := lru.NewWithEvict(size, ts.tokenEviction)
		if err != nil {
			return nil, err
		}
		ts.l.Info("Token caching enabled", zap.Int("size", size))
		ts.Cache = cache
		ts.cacheEnabled = true
	}
	return ts, nil
}

func (ts *TokenStore) tokenEviction(key interface{}, value interface{}) {
	tok, ok := value.(*Token)
	if !ok || tok == nil {
		ts.l.Error(fmt.Sprintf("can't revoke token for key: %+v and value: %+v", key, value))
		return
	}
	tok.Cancel()
}

func (ts *TokenStore) RemoveToken(tok *Token) error {
	tok.Cancel()
	if !ts.cacheEnabled {
		return fmt.Errorf("cache not enabled")
	}
	ts.Cache.Remove(tok.HashKey)
	return nil
}

func (ts *TokenStore) GetToken(jwtTok *jwt.Token) (*Token, error) {
	var tok *Token

	hash := fmt.Sprintf("%x", md5.Sum([]byte(jwtTok.Raw)))
	l := ts.l.With(zap.String("jwt-md5", hash))

	claimMap, ok := jwtTok.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("jwt token claims can't be converted in a map")
	}
	role := ts.rs.RoleFromClaims(claimMap)
	if role == "" {
		return nil, fmt.Errorf("role is empty")
	}

	if ts.cacheEnabled {
		if tRaw, ok := ts.Cache.Get(hash); ok {
			t, ok := tRaw.(*Token)
			if !ok {
				return nil, fmt.Errorf("bad token stored")
			}
			l.Debug("token is in cache")
			tok = t
		}
	}
	if tok == nil {
		l.Debug("Logging in Vault", zap.String("jwt", jwtTok.Raw), zap.String("role", role))
		s, err := ts.Client.Logical().Write(fmt.Sprintf("auth/%s/login", *jwtPath), map[string]interface{}{"jwt": jwtTok.Raw, "role": role})
		if err != nil {
			return nil, err
		}
		if s.Auth == nil || s.Auth.ClientToken == "" {
			return nil, fmt.Errorf("missing client token in response from vault when getting token")
		}
		l = l.With(zap.String("token", s.Auth.ClientToken))
		tok, err = ts.NewToken(s.Auth.ClientToken)
		if err != nil {
			return nil, err
		}
	}
	if ts.cacheEnabled {
		exp, ok := claimMap["exp"]
		if !ok {
			l.Warn("can't determine expiration for vault token from jwt. Will not renew it")
			return tok, nil
		}
		time.AfterFunc(time.Until(time.Unix(int64(exp.(float64)), 0)), func() { ts.RemoveToken(tok) })
		ts.Cache.Add(hash, tok)
		l.Debug("token registered in cache")
	}
	return tok, nil
}
