// Package server runs the redactor as an HTTP service.
package server

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/aviv56470/redactor/internal/redact"
)

// shutdownTimeout is how long a shutdown waits for running requests to finish.
// It should be shorter than Kubernetes' terminationGracePeriodSeconds (30s by
// default), so requests finish before the pod is killed.
const shutdownTimeout = 20 * time.Second

// Handler returns the service's HTTP handler:
//
//	POST /redact   the request body is NDJSON; the response is the redacted NDJSON
//	GET  /healthz  200 when the service is running with its rules loaded
//
// Any other method on these paths gets 405 Method Not Allowed.
func Handler(rules *redact.Rules, logger *log.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /redact", redactHandler(rules, logger))
	mux.HandleFunc("GET /healthz", healthHandler(rules))
	return mux
}

// redactHandler streams the request body through the redactor, one line at a
// time: lines are read, redacted and written back while the client is still
// sending, so neither the request nor the response is held in memory.
func redactHandler(rules *redact.Rules, logger *log.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// With HTTP/1.1, Go's server stops reading the request body once it
		// starts sending the response, unless "full duplex" is switched on.
		// We need both at once to stream.
		_ = http.NewResponseController(w).EnableFullDuplex()

		w.Header().Set("Content-Type", "application/x-ndjson")

		// A Redactor counts what it changes, so it must not be shared
		// between requests running at the same time. The rules themselves
		// are only read, so all requests share them.
		rd := redact.NewRedactor(rules)
		report := func(line int, reason string) {
			logger.Printf("POST /redact: line %d rejected: %s", line, reason)
		}

		stats, err := rd.Process(r.Body, w, report)
		if err != nil {
			// The response has probably started already, so the status can't
			// be changed to an error any more. Abort the connection instead:
			// the client sees a broken response, not one that merely looks
			// shorter, and can't mistake it for the complete output.
			logger.Printf("POST /redact: stopped after %d lines: %v", stats.Lines, err)
			panic(http.ErrAbortHandler)
		}
		logger.Printf("POST /redact: %d lines, %d rejected, %d blank lines skipped",
			stats.Lines, stats.Rejected, stats.Blank)
	}
}

// healthHandler answers health checks. The rules are loaded and checked
// before the server starts listening (if they can't be loaded, the program
// exits instead), so any answer at all means the service can redact.
func healthHandler(rules *redact.Rules) http.HandlerFunc {
	ruleCount := len(rules.KeyRules) + len(rules.ValueRules)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"status":"ok","rules":%d}`+"\n", ruleCount)
	}
}

// Run serves h on addr until ctx is cancelled (for example by SIGTERM when
// Kubernetes stops the pod). It then shuts down gracefully: it stops
// accepting new connections and waits for running requests to finish.
func Run(ctx context.Context, addr string, h http.Handler, logger *log.Logger) error {
	srv := &http.Server{
		Addr:     addr,
		Handler:  h,
		ErrorLog: logger,
		// Don't let a client hold a connection open by sending its
		// headers very slowly. There's no limit on reading the body,
		// because a large log file can take a long time to stream.
		ReadHeaderTimeout: 10 * time.Second,
	}

	// ListenAndServe blocks until the server stops, so it runs in its own
	// goroutine, and its result comes back through a channel.
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.ListenAndServe()
	}()
	logger.Printf("listening on %s", addr)

	// Wait for whichever happens first: the server fails (for example, the
	// port is already in use), or we're told to stop.
	select {
	case err := <-serveErr:
		return err
	case <-ctx.Done():
	}

	logger.Printf("shutting down: waiting up to %s for running requests", shutdownTimeout)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
