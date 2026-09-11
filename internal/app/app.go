// Package app wires the application together. It takes the place of Spring's
// component scanning and dependency injection: every collaborator is
// constructed once, in dependency order, and handed to whoever needs it.
package app

import (
	"database/sql"
	"fmt"
	"io"
	"io/fs"
	"net/http"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/config"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/db"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/logging"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/rest"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security/jwt"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security/repository"
	securityrest "github.com/szerhusenBC/jwt-spring-security-demo/internal/security/rest"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/security/service"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/web"
)

// Resources are the files bundled with the binary: the static client, the seed
// data, and the startup banner.
type Resources struct {
	Static    fs.FS
	ImportSQL string
	Banner    string
}

// Application is a fully wired application.
type Application struct {
	Handler http.Handler
	Config  config.Config

	database *sql.DB
	banner   string
}

// New builds the application. logOutput receives the log stream; closing the
// returned application closes the database.
func New(cfg config.Config, resources Resources, logOutput io.Writer) (*Application, error) {
	database, err := db.Open(resources.ImportSQL)
	if err != nil {
		return nil, err
	}

	loggers := logging.NewFactory(logOutput, cfg.Logging.Root, cfg.Logging.Levels)
	responder := web.NewResponder()

	userRepository := repository.NewUserRepository(database)

	tokenProvider := jwt.NewTokenProvider(
		cfg.JWT.Secret, cfg.JWT.TokenValidity, cfg.JWT.TokenValidityForRememberMe,
		loggers.Logger("org.zerhusen.security.jwt.TokenProvider"))
	jwtFilter := jwt.NewFilter(tokenProvider, loggers.Logger("org.zerhusen.security.jwt.JWTFilter"))

	securityUtils := security.NewSecurityUtils(loggers.Logger("org.zerhusen.security.SecurityUtils"))
	userDetailsService := security.NewUserModelDetailsService(
		userRepository, loggers.Logger("org.zerhusen.security.UserModelDetailsService"))
	authenticationManager := security.NewAuthenticationManager(userDetailsService)

	userService := service.NewUserService(userRepository, securityUtils)

	authenticationController := securityrest.NewAuthenticationController(tokenProvider, authenticationManager, responder)
	userController := securityrest.NewUserController(userService, responder)
	personController := rest.NewPersonController(responder)
	adminProtectedController := rest.NewAdminProtectedController(responder)

	var router *web.Router
	staticHandler := web.NewStaticHandler(resources.Static,
		func(w http.ResponseWriter, r *http.Request) { router.NotFound(w, r) },
		func(w http.ResponseWriter, r *http.Request, allow string) { router.MethodNotAllowed(w, r, allow) },
	)
	router = web.NewRouter(responder, staticHandler,
		web.Route{Method: http.MethodPost, Path: "/api/authenticate", ConsumesJSON: true, Handler: authenticationController.Authorize},
		web.Route{Method: http.MethodGet, Path: "/api/user", Handler: userController.GetActualUser},
		web.Route{Method: http.MethodGet, Path: "/api/person", Handler: personController.GetPerson},
		web.Route{Method: http.MethodGet, Path: "/api/hiddenmessage", Handler: adminProtectedController.GetAdminProtectedGreeting},
	)

	securityConfig := config.NewWebSecurityConfig(
		tokenProvider, jwtFilter,
		security.NewAuthenticationEntryPoint(responder),
		security.NewAccessDeniedHandler(responder),
	)

	// The CORS filter sits outside the security chain, so it also answers the
	// preflights the chain ignores.
	handler := config.NewCorsFilter().Handle(securityConfig.Handler(router))

	return &Application{Handler: handler, Config: cfg, database: database, banner: resources.Banner}, nil
}

// Close releases the database.
func (a *Application) Close() error { return a.database.Close() }

// Addr is the address the server listens on.
func (a *Application) Addr() string { return fmt.Sprintf(":%d", a.Config.Server.Port) }

// Banner returns the startup banner.
func (a *Application) Banner() string { return a.banner }
