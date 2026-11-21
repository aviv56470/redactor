package server

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aviv56470/redactor/internal/redact"
)

// newTestServer starts the service on a random local port, with the
// project's real rules.yaml.
func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	rules, err := redact.LoadRules("../../rules.yaml")
	if err != nil {
		t.Fatalf("LoadRules: %v", err)
	}
	srv := httptest.NewServer(Handler(rules, log.New(io.Discard, "", 0)))
	t.Cleanup(srv.Close)
	return srv
}

func TestRedactEndpoint(t *testing.T) {
	srv := newTestServer(t)

	input := `{"body":{"password":"hunter2"}}` + "\n" +
		"\n" +
		`{"broken":` + "\n"
	want := `{"body":{"password":"****"}}` + "\n" +
		`{"redactor_error":"truncated JSON","line":3}` + "\n"

	resp, err := http.Post(srv.URL+"/redact", "application/x-ndjson", strings.NewReader(input))
	if err != nil {
		t.Fatalf("POST /redact: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/x-ndjson" {
		t.Errorf("Content-Type = %q, want application/x-ndjson", ct)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != want {
		t.Errorf("body\n got: %q\nwant: %q", body, want)
	}
}

// The response must start arriving while the client is still sending the
// request. If the service read the whole body before answering, this test
// would wait until its deadline and fail.
func TestRedactEndpointStreams(t *testing.T) {
	srv := newTestServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// The request body is a pipe: we decide when it ends. If the deadline
	// passes, end it with an error, so the client stops waiting to send more
	// and the test fails instead of hanging.
	bodyReader, bodyWriter := io.Pipe()
	defer bodyWriter.Close()
	go func() {
		<-ctx.Done()
		bodyWriter.CloseWithError(ctx.Err())
	}()

	// Send enough lines to fill the service's output buffer (about 4 KB),
	// but don't end the request.
	go func() {
		line := []byte(`{"body":{"email":"a@b.com","note":"padding padding padding"}}` + "\n")
		for i := 0; i < 200; i++ {
			if _, err := bodyWriter.Write(line); err != nil {
				return
			}
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, srv.URL+"/redact", bodyReader)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /redact: %v (the response never started)", err)
	}
	defer resp.Body.Close()

	first, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil {
		t.Fatalf("reading the first line: %v", err)
	}
	if strings.Contains(first, "a@b.com") || !strings.Contains(first, "sha256:") {
		t.Errorf("first line is not redacted: %s", first)
	}
}

func TestHealthz(t *testing.T) {
	srv := newTestServer(t)

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte(`"status":"ok"`)) {
		t.Errorf("got %d %s, want 200 with status ok", resp.StatusCode, body)
	}
}

func TestWrongMethodIsRejected(t *testing.T) {
	srv := newTestServer(t)

	resp, err := http.Get(srv.URL + "/redact")
	if err != nil {
		t.Fatalf("GET /redact: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("status = %d, want 405", resp.StatusCode)
	}
}

// Run must return when its context is cancelled, the way it is when the
// process receives SIGTERM.
func TestRunStopsWhenCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, "127.0.0.1:0", http.NotFoundHandler(), log.New(io.Discard, "", 0))
	}()

	time.Sleep(100 * time.Millisecond) // let it start listening
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after its context was cancelled")
	}
}
