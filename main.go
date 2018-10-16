package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"regexp"

	"go.uber.org/zap"

	"github.com/uepoch/vault-jwt-proxy/version"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

var (
	verbosity = kingpin.Flag("log-level", "Log level").Short('l').Default("info").Enum("debug", "info")
	role      = kingpin.Flag("role", "The roles to be used against vault server for provided claims.").Short('r').String()
	vaultAddr = kingpin.Flag("vault-addr", "The Vault server's address.").Envar("VAULT_ADDR").Required().URL()
	jwtPath   = kingpin.Flag("vault-jwt-path", "The mount-path used for JWT backend in Vault server").Default("jwt").String()

	tokenCaching = kingpin.Flag("store-size", "Keep a LRU cache for vault tokens to fasten response time. Setting it to 0 will disable it.").Default("50").Int()
	cookieMode   = kingpin.Flag("cookie-mode", "Cookie mode will set a cookie in the response with the JWT").Default("true").Bool()

	bindAddr = kingpin.Flag("bind-addr", "Address to bind the http server").Short('H').Default("127.0.0.1").IP()
	bindPort = kingpin.Flag("bind-port", "Port to bind the http server").Short('p').Default("8080").Envar("JWT_PROXY_PORT").Int()

	devMode          = kingpin.Flag("dev-mode", "Activate debug JWT").Bool()
	claimToRoleStr   = kingpin.Flag("claims-to-role", "If a claim name in client JWT matches a key, it will the role specified as value.").Strings()
	claimToRoleRegex = regexp.MustCompile("=")
)

func SetupLogger(verbosity string) (*zap.Logger, error) {
	if verbosity == "debug" {
		return zap.NewDevelopment()
	}
	return zap.NewProduction()
}

func validateClaimsToRole(cs []string) (map[string]string, error) {
	r := map[string]string{}
	for _, c := range cs {
		cMatches := claimToRoleRegex.Split(c, -1)
		if len(cMatches) != 2 {
			return nil, fmt.Errorf("\"%s\" is not a valid <key>=<value> string", c)
		}
		r[cMatches[0]] = cMatches[1]
	}
	return r, nil
}

func main() {

	kingpin.Version(version.Version)
	kingpin.Parse()

	logger, err := SetupLogger(*verbosity)
	if err != nil {
		fmt.Println("Erorr initializing logger.")
		panic(err)
	}

	var rs RoleAssignator
	claimToRole, err := validateClaimsToRole(*claimToRoleStr)
	if err != nil {
		logger.Fatal("invalid claims-to-role passed", zap.Error(err))
	}

	if (*role == "" && (claimToRole == nil || len(claimToRole) == 0)) || (*role != "" && claimToRole != nil && len(claimToRole) != 0) {
		logger.Fatal("You have to provide either '--role' or '--claims-to-role' parameters.")
	}

	if *role != "" {
		rs = RoleStatic(*role)
	} else {
		rs = RoleMap(claimToRole)
	}

	ts, err := NewTokenStore(*tokenCaching, logger, *vaultAddr, rs)
	if err != nil {
		logger.Fatal("can't create token store", zap.Error(err))
	}
	logger.Info("Token store started.")
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
