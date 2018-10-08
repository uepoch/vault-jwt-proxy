package main

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/hashicorp/golang-lru"
	"github.com/hashicorp/vault/api"
)

type Token struct {
	*api.TokenAuth
	Value           string
	Period          time.Duration
	Refresher       *time.Ticker
	LastRefreshTime time.Time
	ctx             context.Context
}

func (ts *TokenStore) NewToken(value string, period time.Duration) (*Token, error) {
	ctx := context.WithValue(context.Background(), CtxLoggerKey, ts.l.With(zap.String("token-prefix", value[:10])))
	t := &Token{Value: value, Period: period, Refresher: time.NewTicker(period), TokenAuth: ts.Client.Auth().Token(), ctx: ctx}
	t.Bootstrap()
	return t, nil
}

func (t *Token) Logger() *zap.Logger {
	if l, ok := t.ctx.Value(CtxLoggerKey).(*zap.Logger); ok {
		return l
	}
	return zap.NewNop()
}

func (t *Token) Bootstrap() {
	l := t.Logger()
	go func() {
		for range t.Refresher.C {
			t.Refresh()
		}
	}()
	l.Debug("token boostrapped")
}

func (t *Token) Refresh() {
	_, err := t.RenewSelf(1)
	if err != nil {
	}
	t.LastRefreshTime = time.Now()
	t.Logger().Info("token refreshed", zap.Time("refresh-time", t.LastRefreshTime))
}

type TokenStore struct {
	*lru.Cache
	*api.Client
	cacheEnabled bool
	l            *zap.Logger
}

func NewTokenStore(size int, logger *zap.Logger) (*TokenStore, error) {
	t := &TokenStore{}

	t.l = logger

	conf := api.DefaultConfig()
	conf.Address = (*vaultAddr).String()
	if size < 0 {
		return nil, fmt.Errorf("you have to pass a positive value in size for NewTokenStore")
	}
	if size == 0 {
		t.l.Info("Token caching disabled")
		t.cacheEnabled = false
	} else {
		cache, err := lru.NewWithEvict(size, t.tokenEviction)
		if err != nil {
			return nil, err
		}
		t.l = t.l.With(zap.Int("size", size))
		t.l.Info("Token caching enabled")
		t.Cache = cache
		t.cacheEnabled = true
	}
	return t, nil
}

func (ts *TokenStore) tokenEviction(key interface{}, value interface{}) {

	ts.Auth().Token().RevokeSelf(value.(string))
}

func (ts *TokenStore) GetToken(jwt *jwt.Token) (*Token, error) {
	var tok *Token
	if ts.cacheEnabled {
		if tRaw, ok := ts.Cache.Get(jwt.Signature); ok {
			t, ok := tRaw.(*Token)
			if !ok {
				return nil, fmt.Errorf("bad token stored")
			}
			tok = t
		}
	}
	if tok == nil {
		s, err := ts.Logical().Write(fmt.Sprintf("auth/%s/login", jwtPath), map[string]interface{}{"jwt": jwt.Raw, "role": role})
		if err != nil {
			return nil, err
		}
		_ = s
	}
	return tok, nil
}
