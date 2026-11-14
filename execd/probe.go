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
	"strings"
	"time"
)

// probeCommand is a pod's exec probe where the kubelet's own can't reach: it exits 0 on a pass and 1 on a failure.
func probeCommand(args []string) {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	timeout := fs.Duration("timeout", time.Second, "the longest the probe may take")
	fs.Parse(args)
	if fs.NArg() == 0 {
		fail("usage: execd probe [--timeout DURATION] URL [HEADER...]")
	}
	if err := probe(fs.Arg(0), fs.Args()[1:], *timeout); err != nil {
		fmt.Fprintln(os.Stderr, "execd:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// probe checks target once as the kubelet's tcpSocket or httpGet probe would (pkg/probe in kubernetes).
func probe(target string, headers []string, timeout time.Duration) error {
	u, err := url.Parse(target)
	if err != nil {
		return err
	}
	if u.Scheme == "tcp" {
		c, err := net.DialTimeout("tcp", u.Host, timeout)
		if err != nil {
			return err
		}
		return c.Close()
	}
	req, err := http.NewRequest("GET", u.String(), nil)
	if err != nil {
		return err
	}
	for _, h := range headers {
		name, value, _ := strings.Cut(h, ":")
		req.Header.Add(name, strings.TrimSpace(value))
	}
	if _, ok := req.Header["User-Agent"]; !ok {
		req.Header.Set("User-Agent", "kube-probe/execd")
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
