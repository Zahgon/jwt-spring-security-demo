// Command jwtdemo is a demo of JWT authentication over a REST API.
//
// It replaces the Spring Boot application of the same name: the entry point
// loads the configuration, wires the application, prints the banner, and serves
// HTTP until interrupted.
package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/szerhusenBC/jwt-spring-security-demo/internal/app"
	"github.com/szerhusenBC/jwt-spring-security-demo/internal/config"
)

// The configuration, seed data, banner and static client travel inside the
// binary, the way they travelled inside the executable jar.
//
//go:embed config/application.yml
var applicationYAML []byte

//go:embed resources/import.sql
var importSQL string

//go:embed resources/banner.txt
var banner string

//go:embed web/static
var staticFiles embed.FS

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Parse(applicationYAML)
	if err != nil {
		return err
	}

	static, err := fs.Sub(staticFiles, "web/static")
	if err != nil {
		return err
	}

	application, err := app.New(cfg, app.Resources{
		Static:    static,
		ImportSQL: importSQL,
		Banner:    banner,
	}, os.Stdout)
	if err != nil {
		return err
	}
	defer application.Close()

	fmt.Println(application.Banner())

	server := &http.Server{
		Addr:              application.Addr(),
		Handler:           application.Handler,
		ReadHeaderTimeout: 10 * time.Second,
	}

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	serverErrors := make(chan error, 1)
	go func() {
		fmt.Printf("Started JwtDemoApplication on %s\n", server.Addr)
		serverErrors <- server.ListenAndServe()
	}()

	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-shutdown:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	}
}
