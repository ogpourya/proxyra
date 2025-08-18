package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"h12.io/socks"
)

const (
	readLimitBytes = 64 * 1024 // read up to 64 KB
	maxLineBytes   = 1024 * 1024
)

// read proxies from stdin (pipe mode)
func readProxiesFromStdin() ([]string, error) {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return nil, err
	}
	if (fi.Mode() & os.ModeCharDevice) != 0 {
		return nil, nil
	}
	var list []string
	scanner := bufio.NewScanner(os.Stdin)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, maxLineBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			list = append(list, line)
		}
	}
	return list, scanner.Err()
}

// read proxies from file
func readProxiesFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var list []string
	scanner := bufio.NewScanner(f)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, maxLineBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			list = append(list, line)
		}
	}
	return list, scanner.Err()
}

// remove duplicates
func uniqProxies(proxies []string) []string {
	seen := make(map[string]struct{}, len(proxies))
	out := make([]string, 0, len(proxies))
	for _, p := range proxies {
		if _, ok := seen[p]; !ok {
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	return out
}

// build transport with full proxy support (http, socks4, socks4a, socks5)
func newTransport(proxyAddr string, timeout int) (*http.Transport, error) {
	// accept scheme-less proxy like "1.2.3.4:1080" and default to socks5 as common choice
	if !strings.Contains(proxyAddr, "://") {
		proxyAddr = "socks5://" + proxyAddr
	}

	u, err := url.Parse(proxyAddr)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableCompression:  false,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}

	switch u.Scheme {
	case "http", "https":
		transport.Proxy = http.ProxyURL(u)

	case "socks4", "socks4a", "socks5":
		// h12.io/socks returns a dial func of signature func(network, addr string) (net.Conn, error)
		dialSocks := socks.Dial(proxyAddr)

		// Wrap the returned dial function to honor context and avoid leaks.
		// We also use the caller context deadline, which in your code is set by NewRequestWithContext.
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			// If caller already has a deadline, prefer that. Otherwise set an internal timeout.
			// Use the timeout parameter only as a fallback.
			dctx := ctx
			if _, ok := ctx.Deadline(); !ok && timeout > 0 {
				var cancel context.CancelFunc
				dctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
				defer cancel()
			}

			ch := make(chan struct {
				conn net.Conn
				err  error
			}, 1)

			go func() {
				conn, err := dialSocks(network, addr)
				// try to send result; if caller already gave up, close the conn to avoid leak
				select {
				case ch <- struct {
					conn net.Conn
					err  error
				}{conn, err}:
					return
				case <-dctx.Done():
					if err == nil && conn != nil {
						_ = conn.Close()
					}
					return
				}
			}()

			select {
			case <-dctx.Done():
				return nil, dctx.Err()
			case r := <-ch:
				return r.conn, r.err
			}
		}

	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", u.Scheme)
	}

	return transport, nil
}

// check if proxy works
func checkProxy(proxyAddr, target string, timeout int, re *regexp.Regexp) bool {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	transport, err := newTransport(proxyAddr, timeout)
	if err != nil {
		return false
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   time.Duration(timeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil // follow redirects like -L
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	var buf bytes.Buffer
	_, _ = io.CopyN(&buf, resp.Body, int64(readLimitBytes))

	transport.CloseIdleConnections()

	return re.Match(buf.Bytes())
}

// worker
func worker(jobs <-chan string, target string, timeout int, re *regexp.Regexp, out chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	for proxyAddr := range jobs {
		proxyAddr = strings.TrimSpace(proxyAddr)
		if proxyAddr == "" {
			continue
		}
		if checkProxy(proxyAddr, target, timeout, re) {
			out <- proxyAddr
		}
	}
}

func main() {
	target := flag.String("url", "", "Target URL (required)")
	timeout := flag.Int("timeout", 5, "Timeout in seconds")
	threads := flag.Int("threads", 10, "Number of concurrent threads")
	listFile := flag.String("list", "", "File with list of proxies")
	regexStr := flag.String("regex", ".*", "Regex to match response")
	flag.Parse()

	if *target == "" {
		fmt.Fprintln(os.Stderr, "Error: target URL is required")
		os.Exit(1)
	}
	if *timeout <= 0 {
		fmt.Fprintln(os.Stderr, "Error: timeout must be greater than 0")
		os.Exit(1)
	}
	if *threads <= 0 {
		fmt.Fprintln(os.Stderr, "Error: threads must be greater than 0")
		os.Exit(1)
	}
	if *regexStr == "" {
		fmt.Fprintln(os.Stderr, "Error: regex cannot be empty")
		os.Exit(1)
	}

	re, err := regexp.Compile(*regexStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: invalid regex:", err)
		os.Exit(1)
	}

	proxies, err := readProxiesFromStdin()
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error reading proxies from stdin:", err)
		os.Exit(1)
	}

	if len(proxies) == 0 && *listFile != "" {
		proxies, err = readProxiesFromFile(*listFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "Error reading proxies from file:", err)
			os.Exit(1)
		}
	}

	if len(proxies) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no proxies provided")
		os.Exit(1)
	}

	proxies = uniqProxies(proxies)

	jobs := make(chan string, len(proxies))
	out := make(chan string, len(proxies))

	for _, p := range proxies {
		jobs <- p
	}
	close(jobs)

	var wg sync.WaitGroup
	workers := *threads
	if workers > len(proxies) {
		workers = len(proxies)
	}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker(jobs, *target, *timeout, re, out, &wg)
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	for ok := range out {
		_, _ = os.Stdout.WriteString(ok + "\n")
	}
}
