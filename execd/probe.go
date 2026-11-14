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
	timeout := fs.Duration("timeout", time.Second, "the longest the probe may take")
	fs.Parse(args)
	if err := probe(fs.Args(), *timeout); err != nil {
		fmt.Fprintln(os.Stderr, "execd:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// probe checks a port of 127.0.0.1 once, as the kubelet's tcpSocket or httpGet probe checks a pod's (pkg/probe in kubernetes).
func probe(args []string, timeout time.Duration) error {
	switch {
	case len(args) == 2 && args[0] == "tcp":
	case len(args) > 2 && (args[0] == "http" || args[0] == "https"):
	default:
		return errors.New("usage: execd probe [--timeout DURATION] (tcp PORT | http|https PORT PATH [NAME:VALUE...])")
	}
	port, err := strconv.Atoi(args[1])
	if err != nil {
		return err
	}
	host := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	if args[0] == "tcp" {
		c, err := net.DialTimeout("tcp", host, timeout)
		if err != nil {
			return err
		}
		return c.Close()
	}
	u, err := url.Parse(args[2])
	if err != nil { // the kubelet passes on a path it can't parse
		u = &url.URL{Path: args[2]}
	}
	u.Scheme, u.Host = args[0], host
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return err
	}
	for _, h := range args[3:] {
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
		Timeout: timeout,
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
