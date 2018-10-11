package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"

	"go.uber.org/zap"

	"github.com/uepoch/vault-jwt-proxy/version"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	verbosity = kingpin.Flag("log-level", "Log level").Short('l').Default("info").Enum("debug", "info")
	role      = kingpin.Flag("role", "The roles to be used against vault server for provided claims.").Short('r').Required().String()
	vaultAddr = kingpin.Flag("vault-addr", "The Vault server's address.").Envar("VAULT_ADDR").Required().URL()
	jwtPath   = kingpin.Flag("vault-jwt-path", "The mount-path used for JWT backend in Vault server").Default("jwt").String()

	tokenCaching = kingpin.Flag("store-size", "Keep a LRU cache for vault tokens to fasten response time. Setting it to 0 will disable it.").Default("50").Int()
	cookieMode   = kingpin.Flag("cookie-mode", "Cookie mode will set a cookie in the response with the JWT").Default("true").Bool()

	bindAddr = kingpin.Flag("bind-addr", "Address to bind the http server").Short('H').Default("127.0.0.1").IP()
	bindPort = kingpin.Flag("bind-port", "Port to bind the http server").Short('p').Default("8080").Envar("JWT_PROXY_PORT").Int()

	devMode = kingpin.Flag("dev-mode", "Activate debug JWT").Bool()
)

func SetupLogger(verbosity string) (*zap.Logger, error) {
	if verbosity == "debug" {
		return zap.NewDevelopment()
	}
	return zap.NewProduction()
}

func main() {

	kingpin.Version(version.Version)
	kingpin.Parse()

	logger, err := SetupLogger(*verbosity)
	if err != nil {
		fmt.Println("Erorr initializing logger.")
		panic(err)
	}

	ts, err := NewTokenStore(*tokenCaching, logger, *vaultAddr)
	if err != nil {
		logger.Fatal("can't create token store", zap.Error(err))
	}
	s := Server{l: logger, store: ts}

	logger.Info("Server starting...", zap.Int("port", *bindPort), zap.String("addr", bindAddr.String()))
	defer logger.Info("Server stopped.", zap.Int("port", *bindPort), zap.String("addr", bindAddr.String()))
	err = http.ListenAndServe(fmt.Sprintf("%s:%d", bindAddr.String(), *bindPort), http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = (*vaultAddr).Hostname()
		s.LoggerInit(s.JWTExtract(s.VaultTokenAssign(httputil.NewSingleHostReverseProxy(*vaultAddr)))).ServeHTTP(w, r)
	}))
	if err != nil {
		logger.Fatal("server ended with an error", zap.Error(err))
	}
}
