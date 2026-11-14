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
func probeExit(t *testing.T, args ...string) (int, string) {
	cmd := exec.Command(os.Args[0], append([]string{"probe"}, args...)...)
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
	select {
	case code := <-exited:
		cmd.Wait() // for what it said; the reaper has its status
		return code, said.String()
	case <-time.After(2 * probeBudget):
		cmd.Process.Kill()
		t.Fatalf("the probe %q was still running long after its timeout", args)
		return 0, ""
	}
}

// ask is a probe's arguments for a test server, which listens on 127.0.0.1: the budget, then flags, then its scheme and port.
func ask(srv *httptest.Server, flags ...string) []string {
	u, _ := url.Parse(srv.URL)
	return append(append([]string{"--timeout=" + probeBudget.String()}, flags...), u.Scheme, u.Port())
}

func TestTheProbeCommandExitsZeroWhileAPortListensAndOneOnceItIsClosed(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	budget, port := "--timeout="+probeBudget.String(), strconv.Itoa(l.Addr().(*net.TCPAddr).Port)

	if code, said := probeExit(t, budget, "tcp", port); code != 0 {
		t.Fatalf("the probe of a listening port exited %d saying %q, want 0", code, said)
	}
	if code, said := probeExit(t, "--timeout=0s", "tcp", port); code != 2 {
		t.Fatalf("the probe given no time at all exited %d saying %q, want the usage and 2", code, said)
	}
	l.Close()
	if code, said := probeExit(t, budget, "tcp", port); code != 1 || !strings.Contains(said, "connection refused") {
		t.Fatalf("the probe of a closed port exited %d saying %q, want 1 and the refusal", code, said)
	}
}

func TestAProbeEndsAtItsTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // answers nothing until the probe hangs up
	}))
	defer srv.Close()
	defer srv.CloseClientConnections() // lets the handler go if the probe never hung up

	if code, said := probeExit(t, ask(srv, "--timeout=50ms")...); code != 1 || !strings.Contains(said, "timed out") {
		t.Fatalf("a probe that got no answer exited %d saying %q, want 1 once its 50ms were up", code, said)
	}
}

func TestAnHTTPProbePassesOnlyOnAStatusFrom200To399(t *testing.T) {
	for status, pass := range map[int]bool{200: true, 399: true, 400: false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		code, said := probeExit(t, ask(srv)...)
		srv.Close()

		if (code == 0) != pass {
			t.Errorf("a %d answer made the probe exit %d saying %q", status, code, said)
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
		if code, said := probeExit(t, ask(srv, "--path="+path)...); code != 0 {
			t.Errorf("the path %q: the probe exited %d saying %q", path, code, said)
			continue
		}

		if got := <-seen; got.RequestURI != asked || got.Host != srv.Listener.Addr().String() {
			t.Errorf("of the path %q the server was asked for %q as %q, want %q as %q", path, got.RequestURI, got.Host, asked, srv.Listener.Addr())
		}
	}
	// The kubelet's has no host left to ask of this one.
	if code, _ := probeExit(t, ask(srv, "--path=other:8080/health")...); code != 1 {
		t.Errorf("the path %q made the probe exit %d, want 1 with nothing asked", "other:8080/health", code)
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
	if code, _ := probeExit(t, "--timeout="+probeBudget.String(), scheme, strconv.Itoa(l.Addr().(*net.TCPAddr).Port)); code == 0 {
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
		{"its own", []string{"--header=Host:probe.test", "--header=User-Agent:mine", "--header=Accept:", "--header=X-Probe:a\xc2\xa0", "--header=x-probe:b:c"}, "probe.test",
			http.Header{"User-Agent": {"mine"}, "X-Probe": {"a\xc2\xa0", "b:c"}, "Connection": {"close"}}},
	} {
		if code, said := probeExit(t, ask(srv, tc.given...)...); code != 0 {
			t.Fatalf("%s: the probe exited %d saying %q", tc.name, code, said)
		}
		got := <-seen

		if got.Method != "GET" || got.Host != tc.host || !reflect.DeepEqual(got.Header, tc.headers) {
			t.Errorf("%s: the server got %s for host %q with %q, want host %q with %q",
				tc.name, got.Method, got.Host, got.Header, tc.host, tc.headers)
		}
	}
	// A line break ends no value: Go's client refuses to send one, for the kubelet as here.
	if code, _ := probeExit(t, ask(srv, "--header=X-Probe:a\r\n")...); code != 1 {
		t.Errorf("a header value ending in a line break made the probe exit %d, want 1 with nothing sent", code)
	}
}

func TestAnHTTPSProbeChecksNoCertificateAndOffersHTTP2(t *testing.T) {
	seen := make(chan *http.Request, 1)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r }))
	srv.EnableHTTP2 = true
	srv.StartTLS() // with a certificate no one vouches for
	defer srv.Close()

	if code, said := probeExit(t, ask(srv)...); code != 0 {
		t.Fatalf("the probe exited %d saying %q", code, said)
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

	if code, said := probeExit(t, ask(srv, "--path=/here")...); code != 1 || !strings.Contains(said, "503") {
		t.Errorf("a redirect to a failing page of the same host made the probe exit %d saying %q, want 1 and that page's 503", code, said)
	}
	if code, said := probeExit(t, ask(srv, "--path=/elsewhere")...); code != 0 {
		t.Errorf("a redirect to another host made the probe exit %d saying %q, want a pass without following it", code, said)
	}
	if code, said := probeExit(t, ask(srv, "--path=/loop")...); code != 1 || loops.Load() != 10 {
		t.Errorf("a redirect to itself made the probe exit %d saying %q after %d requests, want 1 after 10", code, said, loops.Load())
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

	if code, said := probeExit(t, ask(srv)...); code != 0 {
		t.Fatalf("a body with no end made the probe exit %d saying %q, want a pass", code, said)
	}
}

func TestAnHTTPProbeFailsWhenTheBodyBreaksOff(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		fmt.Fprint(w, "cut short") // the server then drops the connection
	}))
	defer srv.Close()

	if code, said := probeExit(t, ask(srv)...); code != 1 {
		t.Fatalf("a 200 whose body broke off made the probe exit %d saying %q, want 1", code, said)
	}
}
