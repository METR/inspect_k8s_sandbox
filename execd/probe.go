package main

import (
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// probeCommand is a pod's exec probe where the kubelet's own can't reach: it exits 0 on a pass and 1 on a failure.
func probeCommand(args []string) {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	timeout := fs.Duration("timeout", time.Second, "the longest the probe may take, over 0")
	path := fs.String("path", "/", "the path an http or https probe asks for")
	var headers []string
	fs.Func("header", "a NAME:VALUE header of an http or https probe, once for each", func(h string) error {
		headers = append(headers, h)
		return nil
	})
	fs.Parse(args)
	if fs.NArg() != 2 || *timeout <= 0 {
		fail("usage: execd probe [--timeout=DURATION] [--path=PATH] [--header=NAME:VALUE]... tcp|http|https PORT, the DURATION over 0")
	}
	failed := func(err error) {
		fmt.Fprintln(os.Stderr, "execd:", err)
		os.Exit(1)
	}
	// The process ends itself: a server can hold Go's HTTP/2 client past a timeout of its own.
	time.AfterFunc(*timeout, func() { failed(errors.New("timed out")) })
	if err := probe(fs.Arg(0), fs.Arg(1), *path, headers); err != nil {
		failed(err)
	}
	os.Exit(0)
}

// probe checks a port of 127.0.0.1 once, as the kubelet's tcpSocket or httpGet probe checks a pod's (pkg/probe in kubernetes).
func probe(scheme, port, path string, headers []string) error {
	n, err := strconv.Atoi(port)
	if err != nil {
		return err
	}
	host := net.JoinHostPort("127.0.0.1", strconv.Itoa(n))
	switch scheme {
	case "tcp":
		c, err := net.Dial("tcp", host)
		if err != nil {
			return err
		}
		return c.Close()
	case "http", "https":
	default:
		return fmt.Errorf("unsupported scheme %q", scheme)
	}
	u, err := url.Parse(path)
	if err != nil { // the kubelet passes on a path it can't parse
		u = &url.URL{Path: path}
	}
	u.Scheme, u.Host = scheme, host
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return err
	}
	for _, h := range headers {
		name, value, _ := strings.Cut(h, ":")
		req.Header.Add(name, value)
	}
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", "kube-probe/1.36") // the kubelet's own, at the release this follows
	}
	if _, ok := req.Header["Accept"]; !ok {
		req.Header.Set("Accept", "*/*")
	} else if req.Header.Get("Accept") == "" {
		req.Header.Del("Accept")
	}
	req.Host = req.Header.Get("Host")
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
			ForceAttemptHTTP2:  true,
			DisableKeepAlives:  true,
			DisableCompression: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Hostname() != via[0].URL.Hostname() {
				return http.ErrUseLastResponse
			}
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			return nil
		},
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if _, err := io.Copy(io.Discard, io.LimitReader(res.Body, 10<<10)); err != nil {
		return err
	}
	if res.StatusCode < 200 || res.StatusCode >= 400 {
		return fmt.Errorf("HTTP probe failed with statuscode: %d", res.StatusCode)
	}
	return nil
}
