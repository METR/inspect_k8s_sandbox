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
	case <-time.After(probeBudget):
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

// request describes what a test server last got, for a failure's message.
func request(r *http.Request) string {
	if r == nil {
		return "nothing"
	}
	return fmt.Sprintf("%s %s over %s for host %q with %q", r.Method, r.RequestURI, r.Proto, r.Host, r.Header)
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

	if code, said := probeExit(t, ask(srv, "--timeout=50ms")...); code != 1 || !strings.Contains(said, "no answer within 50ms") {
		t.Fatalf("a probe that got no answer exited %d saying %q, want 1 once its 50ms were up", code, said)
	}
}

func TestAnHTTPProbePassesOnAStatusUnder400(t *testing.T) {
	for status, pass := range map[int]bool{399: true, 400: false} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		code, said := probeExit(t, ask(srv)...)
		srv.Close()

		if (code == 0) != pass {
			t.Errorf("a %d answer made the probe exit %d saying %q", status, code, said)
		}
	}
}

func TestAnHTTPProbeAsksForWhatTheKubeletWouldOfAPath(t *testing.T) {
	var last atomic.Pointer[http.Request]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { last.Store(r) }))
	defer srv.Close()
	// Hawk's encoding of //other/health, /health% and /health?a=b&c, and what kubelet 1.36 asks for.
	for path, asked := range map[string]string{
		"--path=//other/health":      "/health",
		"--path=/health%25":          "/health%25",
		"--path=/health%3Fa%3Db%26c": "/health?a=b&c",
	} {
		code, said := probeExit(t, ask(srv, path)...)

		if got := last.Swap(nil); code != 0 || got == nil || got.RequestURI != asked || got.Host != srv.Listener.Addr().String() {
			t.Errorf("given %s the server got %s and the probe exited %d saying %q, want it asked for %q as %q",
				path, request(got), code, said, asked, srv.Listener.Addr())
		}
	}
}

func TestAnHTTPProbeSendsTheKubeletsHeadersUnlessItIsGivenItsOwn(t *testing.T) {
	var last atomic.Pointer[http.Request]
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { last.Store(r) }))
	defer srv.Close()
	for _, tc := range []struct {
		name    string
		given   []string
		host    string
		headers http.Header
	}{
		{"none given", nil, srv.Listener.Addr().String(),
			http.Header{"User-Agent": {"kube-probe/1.36"}, "Accept": {"*/*"}, "Connection": {"close"}}},
		// A value is the bytes after the first colon, as themselves or as %XX: the kubelet sends on a non-breaking space that ends one.
		{"its own", []string{"--header=Host:probe.test", "--header=User-Agent:mine", "--header=Accept:", "--header=X-Probe:a%C2%A0", "--header=x-probe:b:c%3Ad"}, "probe.test",
			http.Header{"User-Agent": {"mine"}, "X-Probe": {"a\xc2\xa0", "b:c:d"}, "Connection": {"close"}}},
	} {
		code, said := probeExit(t, ask(srv, tc.given...)...)

		if got := last.Swap(nil); code != 0 || got == nil || got.Method != "GET" || got.Host != tc.host || !reflect.DeepEqual(got.Header, tc.headers) {
			t.Errorf("%s: the server got %s and the probe exited %d saying %q, want a GET for host %q with %q",
				tc.name, request(got), code, said, tc.host, tc.headers)
		}
	}
}

func TestAnHTTPSProbeChecksNoCertificateAndOffersHTTP2(t *testing.T) {
	var last atomic.Pointer[http.Request]
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { last.Store(r) }))
	srv.EnableHTTP2 = true
	srv.StartTLS() // with a certificate no one vouches for
	defer srv.Close()

	code, said := probeExit(t, ask(srv)...)

	if got := last.Load(); code != 0 || got == nil || got.ProtoMajor != 2 {
		t.Fatalf("the server got %s and the probe exited %d saying %q, want a pass over HTTP/2, which the kubelet's probe uses when offered", request(got), code, said)
	}
}

func TestAnHTTPProbeFollowsARedirectOnlyToItsOwnHost(t *testing.T) {
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer failing.Close()
	var loops atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/another-port": // of the same host, which is all the kubelet compares
			http.Redirect(w, r, failing.URL, http.StatusFound)
		case "/another-name": // the same failing server, as another host
			http.Redirect(w, r, strings.Replace(failing.URL, "127.0.0.1", "localhost", 1), http.StatusFound)
		case "/loop":
			loops.Add(1)
			http.Redirect(w, r, "/loop", http.StatusFound)
		}
	}))
	defer srv.Close()

	if code, said := probeExit(t, ask(srv, "--path=/another-port")...); code != 1 || !strings.Contains(said, "503") {
		t.Errorf("a redirect to a failing page of the same host made the probe exit %d saying %q, want 1 and that page's 503", code, said)
	}
	if code, said := probeExit(t, ask(srv, "--path=/another-name")...); code != 0 {
		t.Errorf("a redirect to another host made the probe exit %d saying %q, want a pass without following it", code, said)
	}
	if code, said := probeExit(t, ask(srv, "--path=/loop")...); code != 1 || loops.Load() != 10 {
		t.Errorf("a redirect to itself made the probe exit %d saying %q after %d requests, want 1 after 10", code, said, loops.Load())
	}
}

func TestAnHTTPProbeReadsTenKiBOfABodyAndNoMore(t *testing.T) {
	// A body that breaks off: within the kubelet's 10 KiB the probe meets the break, past them it never looks.
	for sent, pass := range map[int]bool{5 << 10: false, 12 << 10: true} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(20<<10))
			w.Write(make([]byte, sent)) // the server then drops the connection
		}))
		code, said := probeExit(t, ask(srv)...)
		srv.Close()

		if (code == 0) != pass {
			t.Errorf("a body that broke off after %d bytes made the probe exit %d saying %q", sent, code, said)
		}
	}
}
