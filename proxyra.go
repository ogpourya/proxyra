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
	"net/http/httputil"
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
func newTransport(proxyAddr string, timeout float64, insecure bool) (*http.Transport, error) {
	// accept scheme-less proxy like "1.2.3.4:1080" and default to socks5 as common choice
	if !strings.Contains(proxyAddr, "://") {
		proxyAddr = "socks5://" + proxyAddr
	}

	u, err := url.Parse(proxyAddr)
	if err != nil {
		return nil, err
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: insecure,
			MinVersion:         tls.VersionTLS12,
		},
		DisableCompression:  false,
		MaxIdleConns:        0,
		IdleConnTimeout:     0,
		MaxIdleConnsPerHost: -1,
		DisableKeepAlives:   true,
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
			var cancel context.CancelFunc
			if _, ok := ctx.Deadline(); !ok && timeout > 0 {
				dctx, cancel = context.WithTimeout(ctx, time.Duration(timeout*float64(time.Second)))
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
				}{
					conn: conn,
					err:  err,
				}:
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
				if cancel != nil {
					cancel()
				}
				return nil, dctx.Err()
			case r := <-ch:
				if cancel != nil {
					cancel()
				}
				return r.conn, r.err
			}
		}

	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", u.Scheme)
	}

	return transport, nil
}

// check if proxy works with TCP mode
func checkProxyTCP(proxyAddr, target string, timeout float64) bool {
	// accept scheme-less proxy like "1.2.3.4:1080" and default to socks5
	if !strings.Contains(proxyAddr, "://") {
		proxyAddr = "socks5://" + proxyAddr
	}

	u, err := url.Parse(proxyAddr)
	if err != nil {
		return false
	}

	var conn net.Conn
	timeoutDuration := time.Duration(timeout * float64(time.Second))

	switch u.Scheme {
	case "socks4", "socks4a", "socks5":
		dialSocks := socks.Dial(proxyAddr)
		ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
		defer cancel()

		ch := make(chan struct {
			conn net.Conn
			err  error
		}, 1)

		go func() {
			c, e := dialSocks("tcp", target)
			select {
			case ch <- struct {
				conn net.Conn
				err  error
			}{conn: c, err: e}:
			case <-ctx.Done():
				if e == nil && c != nil {
					c.Close()
				}
			}
		}()

		select {
		case <-ctx.Done():
			return false
		case r := <-ch:
			if r.err != nil {
				return false
			}
			conn = r.conn
		}

	case "http", "https":
		proxyConn, err := net.DialTimeout("tcp", u.Host, timeoutDuration)
		if err != nil {
			return false
		}

		connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		proxyConn.SetDeadline(time.Now().Add(timeoutDuration))
		_, err = proxyConn.Write([]byte(connectReq))
		if err != nil {
			proxyConn.Close()
			return false
		}

		br := bufio.NewReader(proxyConn)
		line, err := br.ReadString('\n')
		if err != nil {
			proxyConn.Close()
			return false
		}

		// Parse HTTP status line properly
		parts := strings.Fields(line)
		if len(parts) < 2 || (parts[1] != "200" && !strings.HasPrefix(parts[1], "2")) {
			proxyConn.Close()
			return false
		}

		// read until empty line (end of headers)
		for {
			line, err = br.ReadString('\n')
			if err != nil {
				proxyConn.Close()
				return false
			}
			if line == "\r\n" || line == "\n" {
				break
			}
		}

		conn = proxyConn

	default:
		return false
	}

	if conn != nil {
		conn.Close()
		return true
	}
	return false
}

// check if proxy works with HTTP mode
func checkProxyHTTP(proxyAddr, target string, timeout float64, re *regexp.Regexp, insecure bool, expectedStatus int, headers []string, stderrMutex *sync.Mutex) bool {
	// If target is "SMART_MODE", we try multiple IP services sequentially
	if target == "SMART_MODE" {
		services := []string{
			"http://icanhazip.com",
			"https://checkip.amazonaws.com",
			"https://a.ident.me",
		}

		// Determine expected IP once
		host := proxyAddr
		if strings.Contains(host, "://") {
			u, _ := url.Parse(host)
			if u != nil {
				host = u.Host
			}
		}
		ip, _, err := net.SplitHostPort(host)
		if err != nil {
			ip = host
		}
		ipRe, _ := regexp.Compile(regexp.QuoteMeta(strings.TrimSpace(ip)))

		for _, svc := range services {
			if performHTTPCheck(proxyAddr, svc, timeout, ipRe, insecure, expectedStatus, headers, stderrMutex) {
				return true
			}
		}
		return false
	}

	return performHTTPCheck(proxyAddr, target, timeout, re, insecure, expectedStatus, headers, stderrMutex)
}

func performHTTPCheck(proxyAddr, target string, timeout float64, re *regexp.Regexp, insecure bool, expectedStatus int, headers []string, stderrMutex *sync.Mutex) bool {
	timeoutDuration := time.Duration(timeout * float64(time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()

	transport, err := newTransport(proxyAddr, timeout, insecure)
	if err != nil {
		return false
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeoutDuration,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false
	}

	// Add custom headers
	for _, h := range headers {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) != 2 {
			stderrMutex.Lock()
			fmt.Fprintf(os.Stderr, "Warning: ignoring malformed header: %s\n", h)
			stderrMutex.Unlock()
			continue
		}
		req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Check expected status code if specified
	if expectedStatus > 0 && resp.StatusCode != expectedStatus {
		return false
	}

	// Read body up to limit
	var buf bytes.Buffer
	_, _ = io.CopyN(&buf, resp.Body, int64(readLimitBytes))

	// Dump headers (false = do not dump body yet)
	headerDump, err := httputil.DumpResponse(resp, false)
	if err != nil {
		headerDump = []byte{}
	}

	var fullResponse bytes.Buffer
	fullResponse.Write(headerDump)
	fullResponse.Write(buf.Bytes())

	transport.CloseIdleConnections()

	return re.Match(fullResponse.Bytes())
}

// worker
func worker(jobs <-chan string, target string, timeout float64, re *regexp.Regexp, out chan<- string, wg *sync.WaitGroup, insecure bool, checkCount int, tcpMode bool, expectedStatus int, headers []string, maxFound *int, maxMutex *sync.Mutex, done chan struct{}, stderrMutex *sync.Mutex) {
	defer wg.Done()
	for proxyAddr := range jobs {
		// Check if we should stop early
		select {
		case <-done:
			return
		default:
		}

		passed := 0
		for i := 0; i < checkCount; i++ {
			var success bool
			if tcpMode {
				success = checkProxyTCP(proxyAddr, target, timeout)
			} else {
				success = checkProxyHTTP(proxyAddr, target, timeout, re, insecure, expectedStatus, headers, stderrMutex)
			}
			if success {
				passed++
			} else if checkCount > 1 {
				// Early exit: if we need all checks to pass and one failed, no point continuing
				break
			}
		}
		if passed == checkCount {
			if maxFound != nil {
				maxMutex.Lock()
				if *maxFound > 0 {
					out <- proxyAddr
					*maxFound--
					if *maxFound == 0 {
						// Signal completion using sync.Once pattern
						select {
						case <-done:
							// Already closed
						default:
							close(done)
						}
					}
				}
				maxMutex.Unlock()
			} else {
				out <- proxyAddr
			}
		}
	}
}

type headerFlags []string

func (h *headerFlags) String() string {
	return strings.Join(*h, ", ")
}

func (h *headerFlags) Set(value string) error {
	*h = append(*h, value)
	return nil
}

func main() {
	target := flag.String("u", "", "Target URL or address (required if -tcp is used)")
	timeout := flag.Float64("t", 5.0, "Timeout in seconds (float, e.g. 1.5)")
	threads := flag.Int("c", 10, "Concurrency (number of threads)")
	listFile := flag.String("l", "", "File with list of proxies")
	regexStr := flag.String("r", "", "Regex to match response (headers or body)")
	insecure := flag.Bool("k", false, "Allow insecure TLS connections (disabled by default)")
	checkCount := flag.Int("n", 1, "Number of times a proxy must pass checks to be valid")
	tcpMode := flag.Bool("tcp", false, "TCP connection mode (test raw TCP connection instead of HTTP)")
	maxFound := flag.Int("m", 0, "Stop after finding N valid proxies (0 = unlimited)")
	expectedStatus := flag.Int("s", 0, "Expected HTTP status code (0 = any status)")
	var headers headerFlags
	flag.Var(&headers, "H", "Custom request header (can be used multiple times, e.g. -H \"User-Agent: custom\")")
	flag.Parse()

	if *target == "" && !*tcpMode {
		*target = "SMART_MODE"
	}

	if *target == "" && *tcpMode {
		fmt.Fprintln(os.Stderr, "Error: target URL or address is required when using -tcp")
		flag.PrintDefaults()
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
	if *checkCount <= 0 {
		fmt.Fprintln(os.Stderr, "Error: check count must be greater than 0")
		os.Exit(1)
	}
	if *maxFound < 0 {
		fmt.Fprintln(os.Stderr, "Error: max found must be >= 0")
		os.Exit(1)
	}
	if *expectedStatus < 0 {
		fmt.Fprintln(os.Stderr, "Error: expected status must be >= 0")
		os.Exit(1)
	}
	if *tcpMode {
		// TCP mode: validate target format (host:port)
		if !strings.Contains(*target, ":") {
			fmt.Fprintln(os.Stderr, "Error: TCP mode requires target in host:port format")
			os.Exit(1)
		}
	} else if *target != "SMART_MODE" {
		// HTTP mode: validate URL format
		if !strings.HasPrefix(*target, "http://") && !strings.HasPrefix(*target, "https://") {
			fmt.Fprintln(os.Stderr, "Error: HTTP mode requires target URL starting with http:// or https://")
			os.Exit(1)
		}
	}

	// For the fallback mechanism, regex is the proxy's IP.
	// We handle this inside the worker or by compiling a placeholder here.
	if *regexStr == "" {
		if *target == "SMART_MODE" {
			*regexStr = ".*" // Placeholder, logic handled in checkProxyHTTP
		} else {
			*regexStr = ".*"
		}
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

	// Use smaller buffer to avoid excessive memory with large proxy lists
	bufferSize := 100
	if len(proxies) < bufferSize {
		bufferSize = len(proxies)
	}
	jobs := make(chan string, bufferSize)
	out := make(chan string, bufferSize)

	var maxFoundPtr *int
	var maxMutex sync.Mutex
	var stderrMutex sync.Mutex
	done := make(chan struct{})
	if *maxFound > 0 {
		maxFoundCopy := *maxFound
		maxFoundPtr = &maxFoundCopy
	}

	var wg sync.WaitGroup
	workers := *threads
	if workers > len(proxies) {
		workers = len(proxies)
	}
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go worker(jobs, *target, *timeout, re, out, &wg, *insecure, *checkCount, *tcpMode, *expectedStatus, headers, maxFoundPtr, &maxMutex, done, &stderrMutex)
	}

	// Feed jobs to workers
	go func() {
		defer close(jobs)
		for _, p := range proxies {
			select {
			case jobs <- p:
			case <-done:
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(out)
	}()

	for ok := range out {
		_, _ = os.Stdout.WriteString(ok + "\n")
	}
}
