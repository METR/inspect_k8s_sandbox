package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A probe that should pass gets this long: it only bounds a hang.
const probeBudget = 30 * time.Second

// probeExit runs the probe command and returns its exit status, which the tests' reaper collects, and what it said.
func probeExit(t *testing.T, check ...string) (int, string) {
	cmd := exec.Command(os.Args[0], append([]string{"probe", "--timeout", probeBudget.String()}, check...)...)
	var said strings.Builder
	cmd.Stderr = &said
	reaper.mu.Lock() // so the reaper cannot collect the exit before it is watched
	err := cmd.Start()
	var exited chan int
	if err == nil {
		exited = reaper.watch(cmd.Process.Pid)
	}
	reaper.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	code := <-exited // its own timeout bounds this
	cmd.Wait()       // for what it said; the reaper has its status
	return code, said.String()
}

// ask is a probe's arguments for a path of a test server, which listens on 127.0.0.1.
func ask(srv *httptest.Server, path string, headers ...string) []string {
	u, _ := url.Parse(srv.URL)
	return append([]string{u.Scheme, u.Port(), path}, headers...)
}

func TestTheProbeCommandExitsZeroWhileAPortListensAndOneOnceItIsClosed(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)

	if code, said := probeExit(t, "tcp", port); code != 0 {
		t.Fatalf("the probe of a listening port exited %d saying %q, want 0", code, said)
	}
	l.Close()
	if code, said := probeExit(t, "tcp", port); code != 1 || !strings.Contains(said, "connection refused") {
		t.Fatalf("the probe of a closed port exited %d saying %q, want 1 and the refusal", code, said)
	}
}

func TestAnHTTPProbePassesOnlyOnAStatusFrom200To399(t *testing.T) {
	for status, pass := range map[int]bool{200: true, 399: true, 400: false, 503: false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		err := probe(ask(srv, "/"), probeBudget)
		srv.Close()

		if (err == nil) != pass {
			t.Errorf("a %d answer gave %v", status, err)
		}
	}
}

func TestAnHTTPProbeAsksForWhatTheKubeletWouldOfAPath(t *testing.T) {
	seen := make(chan *http.Request, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r }))
	defer srv.Close()
	// What a server got of each path from the kubelet's own formatURL and request (kubernetes 1.36, pkg/probe/http/request.go).
	for path, asked := range map[string]string{
		"/health":             "/health",
		"health":              "/health",
		"":                    "/",
		"//other/health":      "/health",
		"http://other/health": "/health",
		"/health%":            "/health%25",
		"/health?a=b&c":       "/health?a=b&c",
		"/a b":                "/a%20b",
		"/health#part":        "/health",
	} {
		if err := probe(ask(srv, path), probeBudget); err != nil {
			t.Errorf("the path %q: %v", path, err)
			continue
		}

		if got := <-seen; got.RequestURI != asked || got.Host != srv.Listener.Addr().String() {
			t.Errorf("of the path %q the server was asked for %q as %q, want %q as %q", path, got.RequestURI, got.Host, asked, srv.Listener.Addr())
		}
	}
	// The kubelet's has no host left to ask of this one.
	if err := probe(ask(srv, "other:8080/health"), probeBudget); err == nil {
		t.Errorf("the path %q was asked for as %q", "other:8080/health", (<-seen).RequestURI)
	}
}

func TestAProbesSchemeCannotNameAnotherHost(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer other.Close()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l.Close() // the port the probe names has nothing on it

	scheme := other.URL + "/#"
	if err := probe([]string{scheme, strconv.Itoa(l.Addr().(*net.TCPAddr).Port), "/"}, probeBudget); err == nil {
		t.Fatalf("a probe with the scheme %q passed: it asked the server that names", scheme)
	}
}

func TestAnHTTPProbeSendsTheKubeletsHeadersUnlessItIsGivenItsOwn(t *testing.T) {
	seen := make(chan *http.Request, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r }))
	defer srv.Close()
	for _, tc := range []struct {
		name    string
		given   []string
		host    string
		headers http.Header
	}{
		{"none given", nil, srv.Listener.Addr().String(),
			http.Header{"User-Agent": {"kube-probe/1.36"}, "Accept": {"*/*"}, "Connection": {"close"}}},
		// A value is the bytes after the first colon: the kubelet sends on a non-breaking space that ends one.
		{"its own", []string{"Host:probe.test", "User-Agent:mine", "Accept:", "X-Probe:a ", "x-probe:b:c"}, "probe.test",
			http.Header{"User-Agent": {"mine"}, "X-Probe": {"a ", "b:c"}, "Connection": {"close"}}},
	} {
		if err := probe(ask(srv, "/healthz", tc.given...), probeBudget); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		got := <-seen

		if got.Method != "GET" || got.Host != tc.host || !reflect.DeepEqual(got.Header, tc.headers) {
			t.Errorf("%s: the server got %s for host %q with %q, want host %q with %q",
				tc.name, got.Method, got.Host, got.Header, tc.host, tc.headers)
		}
	}
	// A line break ends no value: Go's client refuses to send one, for the kubelet as here.
	if err := probe(ask(srv, "/healthz", "X-Probe:a\r\n"), probeBudget); err == nil {
		t.Errorf("a header value ending in a line break was sent as %q", (<-seen).Header["X-Probe"])
	}
}

func TestAnHTTPSProbeChecksNoCertificateAndOffersHTTP2(t *testing.T) {
	seen := make(chan *http.Request, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r }))
	srv.EnableHTTP2 = true
	srv.StartTLS() // with a certificate no one vouches for
	defer srv.Close()

	if err := probe(ask(srv, "/"), probeBudget); err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got.ProtoMajor != 2 {
		t.Fatalf("the server was asked over %s, want HTTP/2 as the kubelet's probe uses when offered", got.Proto)
	}
}

func TestAnHTTPProbeFollowsARedirectOnlyToItsOwnHost(t *testing.T) {
	var loops atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/here":
			http.Redirect(w, r, "/failing", http.StatusFound)
		case "/elsewhere": // the same server under another name
			http.Redirect(w, r, strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)+"/failing", http.StatusFound)
		case "/loop":
			loops.Add(1)
			http.Redirect(w, r, "/loop", http.StatusFound)
		default:
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()

	if err := probe(ask(srv, "/here"), probeBudget); err == nil || !strings.Contains(err.Error(), "503") {
		t.Errorf("a redirect to a failing page of the same host gave %v, want that page's 503", err)
	}
	if err := probe(ask(srv, "/elsewhere"), probeBudget); err != nil {
		t.Errorf("a redirect to another host gave %v, want a pass without following it", err)
	}
	if err := probe(ask(srv, "/loop"), probeBudget); err == nil || loops.Load() != 10 {
		t.Errorf("a redirect to itself gave %v after %d requests, want a failure after 10", err, loops.Load())
	}
}

func TestAnHTTPProbePassesWithoutReadingABodyToItsEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for chunk := make([]byte, 4096); ; { // until the probe hangs up
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	if err := probe(ask(srv, "/"), probeBudget); err != nil {
		t.Fatalf("a body with no end gave %v, want a pass", err)
	}
}

func TestAnHTTPProbeFailsWhenTheBodyBreaksOff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		fmt.Fprint(w, "cut short") // the server then drops the connection
	}))
	defer srv.Close()

	if err := probe(ask(srv, "/"), probeBudget); err == nil {
		t.Fatal("a 200 whose body broke off passed")
	}
}

func TestAnHTTPProbeGivesUpAtItsTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // answers nothing until the probe hangs up
	}))
	defer srv.Close()
	defer srv.CloseClientConnections() // lets the handler go if the probe never hung up
	done := make(chan error, 1)

	go func() { done <- probe(ask(srv, "/"), 50*time.Millisecond) }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a probe that got no answer passed")
		}
	case <-time.After(probeBudget):
		t.Fatal("the probe was still waiting long after its timeout")
	}
}
