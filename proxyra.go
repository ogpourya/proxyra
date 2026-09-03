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
	"strconv"
	"strings"
	"sync"
	"time"

	"h12.io/socks"

	"github.com/ogpourya/proxyra/xray"
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

func isXrayLink(s string) bool {
	s = strings.TrimSpace(s)
	return strings.HasPrefix(s, "vless://") ||
		strings.HasPrefix(s, "vmess://") ||
		strings.HasPrefix(s, "trojan://") ||
		strings.HasPrefix(s, "ss://") ||
		strings.HasPrefix(s, "hysteria2://") ||
		strings.HasPrefix(s, "hy2://") ||
		strings.HasPrefix(s, "wireguard://") ||
		strings.HasPrefix(s, "wg://")
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
func newTransport(proxyAddr string, timeout float64, insecure bool, noDNS bool) (http.RoundTripper, error) {
	// accept scheme-less proxy like "1.2.3.4:1080" and default to socks5 as common choice
	if !strings.Contains(proxyAddr, "://") {
		proxyAddr = "socks5://" + proxyAddr
	}

	u, err := url.Parse(proxyAddr)
	if err != nil {
		return nil, err
	}

	proxyHost := u.Host
	isSOCKS := false
	switch u.Scheme {
	case "socks4", "socks4a", "socks5", "socks5h":
		isSOCKS = true
	case "http", "https":
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", u.Scheme)
	}

	if noDNS {
		return &noDNSRoundTripper{
			proxyAddr: proxyHost,
			isSOCKS:   isSOCKS,
			timeout:   time.Duration(timeout * float64(time.Second)),
			insecure:  insecure,
		}, nil
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

	case "socks4", "socks4a", "socks5", "socks5h":
		dialSocks := socks.Dial(strings.Replace(proxyAddr, "socks5h://", "socks5://", 1))
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
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
	}

	return transport, nil
}

// noDNSRoundTripper sends requests through a proxy without resolving DNS locally.
// SOCKS5 uses ATYP 0x03 (domain); HTTP CONNECT sends the hostname as-is.
type noDNSRoundTripper struct {
	proxyAddr string
	isSOCKS   bool
	timeout   time.Duration
	insecure  bool
}

func (rt *noDNSRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	target := req.URL.Host
	if req.URL.Port() == "" {
		if req.URL.Scheme == "https" {
			target = net.JoinHostPort(req.URL.Host, "443")
		} else {
			target = net.JoinHostPort(req.URL.Host, "80")
		}
	}

	conn, err := net.DialTimeout("tcp", rt.proxyAddr, rt.timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if rt.isSOCKS {
		if err := rt.socks5Handshake(conn, target); err != nil {
			return nil, err
		}
	} else {
		if err := rt.httpConnect(conn, target); err != nil {
			return nil, err
		}
	}

	var tunnel net.Conn = conn
	if req.URL.Scheme == "https" {
		tlsConn := tls.Client(tunnel, &tls.Config{
			ServerName:         req.URL.Hostname(),
			InsecureSkipVerify: rt.insecure,
			MinVersion:         tls.VersionTLS12,
		})
		if err := tlsConn.Handshake(); err != nil {
			return nil, err
		}
		tunnel = tlsConn
	}

	if err := req.Write(tunnel); err != nil {
		return nil, err
	}
	return http.ReadResponse(bufio.NewReader(tunnel), req)
}

func (rt *noDNSRoundTripper) CloseIdleConnections() {}

func (rt *noDNSRoundTripper) socks5Handshake(conn net.Conn, target string) error {
	conn.SetDeadline(time.Now().Add(rt.timeout))
	defer conn.SetDeadline(time.Time{})

	conn.Write([]byte{0x05, 0x01, 0x00})
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fmt.Errorf("socks5 auth not supported")
	}

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, _ := strconv.Atoi(portStr)

	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return err
	}

	resp = make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("socks5 connect failed: %d", resp[1])
	}

	switch resp[3] {
	case 0x01:
		io.ReadFull(conn, make([]byte, 6))
	case 0x03:
		l := make([]byte, 1)
		io.ReadFull(conn, l)
		io.ReadFull(conn, make([]byte, int(l[0])+2))
	case 0x04:
		io.ReadFull(conn, make([]byte, 18))
	}
	return nil
}

func (rt *noDNSRoundTripper) httpConnect(conn net.Conn, target string) error {
	conn.SetDeadline(time.Now().Add(rt.timeout))
	defer conn.SetDeadline(time.Time{})

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		return err
	}

	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	if !strings.Contains(line, " 200 ") {
		return fmt.Errorf("CONNECT failed: %s", strings.TrimSpace(line))
	}
	for {
		line, err = br.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	return nil
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
	case "socks4", "socks4a", "socks5", "socks5h":
		dialSocks := socks.Dial(strings.Replace(proxyAddr, "socks5h://", "socks5://", 1))
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
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	return ip.IsPrivate() || ip.IsLoopback()
}

func checkProxyHTTP(proxyAddr, target string, timeout float64, re *regexp.Regexp, insecure bool, noDNS bool, expectedStatus int, headers []string, stderrMutex *sync.Mutex) bool {
	if target == "SMART_MODE" {
		services := []string{
			"http://icanhazip.com",
			"https://checkip.amazonaws.com",
			"https://a.ident.me",
		}

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
		ip = strings.TrimSpace(ip)

		if isPrivateIP(ip) || ip == "localhost" {
			for _, svc := range services {
				if performHTTPCheck(proxyAddr, svc, timeout, re, insecure, noDNS, expectedStatus, headers, stderrMutex) {
					return true
				}
			}
			return false
		}

		ipRe, _ := regexp.Compile(regexp.QuoteMeta(ip))

		for _, svc := range services {
			if performHTTPCheck(proxyAddr, svc, timeout, ipRe, insecure, noDNS, expectedStatus, headers, stderrMutex) {
				return true
			}
		}
		return false
	}

	return performHTTPCheck(proxyAddr, target, timeout, re, insecure, noDNS, expectedStatus, headers, stderrMutex)
}

func performHTTPCheck(proxyAddr, target string, timeout float64, re *regexp.Regexp, insecure bool, noDNS bool, expectedStatus int, headers []string, stderrMutex *sync.Mutex) bool {
	timeoutDuration := time.Duration(timeout * float64(time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), timeoutDuration)
	defer cancel()

	transport, err := newTransport(proxyAddr, timeout, insecure, noDNS)
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

	_ = transport

	return re.Match(fullResponse.Bytes())
}

// worker
func worker(jobs <-chan string, target string, timeout float64, re *regexp.Regexp, out chan<- string, wg *sync.WaitGroup, insecure bool, noDNS bool, checkCount int, tcpMode bool, expectedStatus int, headers []string, maxFound *int, maxMutex *sync.Mutex, done chan struct{}, stderrMutex *sync.Mutex) {
	defer wg.Done()
	for proxyAddr := range jobs {
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
				success = checkProxyHTTP(proxyAddr, target, timeout, re, insecure, noDNS, expectedStatus, headers, stderrMutex)
			}
			if success {
				passed++
			} else if checkCount > 1 {
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
	noDNS := flag.Bool("no-dns", true, "Skip local DNS resolution; pass hostnames as-is to upstream proxies")
	checkCount := flag.Int("n", 1, "Number of times a proxy must pass checks to be valid")
	tcpMode := flag.Bool("tcp", false, "TCP connection mode (test raw TCP connection instead of HTTP)")
	maxFound := flag.Int("m", 0, "Stop after finding N valid proxies (0 = unlimited)")
	verbose := flag.Bool("v", false, "Verbose logging")
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

	// Convert xray config links (vless://, vmess://, etc.) to local SOCKS5 proxies via xray
	var xrayMgr *xray.Manager
	proxyMap := make(map[string]string) // localSocks5Addr -> originalXrayLink
	for i, p := range proxies {
		if isXrayLink(p) {
			if xrayMgr == nil {
				xrayMgr = xray.NewManager()
				xrayMgr.Verbose = *verbose
			}
			ob, err := xray.ParseLink(p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error parsing xray config link: %v\n", err)
				continue
			}
			inst, err := xrayMgr.AddOutbound(ob)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error adding xray outbound: %v\n", err)
				continue
			}
			localAddr := fmt.Sprintf("socks5://127.0.0.1:%d", inst.Port)
			proxyMap[localAddr] = p
			proxies[i] = localAddr
		}
	}
	if xrayMgr != nil {
		if err := xrayMgr.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting xray: %v\n", err)
			os.Exit(1)
		}
		defer xrayMgr.StopAll()
		// Drop quarantined links (no xray instance): nothing listens on their ports.
		livePorts := make(map[string]struct{})
		for _, inst := range xrayMgr.Instances() {
			livePorts[fmt.Sprintf("socks5://127.0.0.1:%d", inst.Port)] = struct{}{}
		}
		kept := proxies[:0]
		for _, p := range proxies {
			if _, isXray := proxyMap[p]; !isXray {
				kept = append(kept, p)
				continue
			}
			if _, ok := livePorts[p]; ok {
				kept = append(kept, p)
			} else {
				delete(proxyMap, p)
			}
		}
		proxies = kept
	}

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
		go worker(jobs, *target, *timeout, re, out, &wg, *insecure, *noDNS, *checkCount, *tcpMode, *expectedStatus, headers, maxFoundPtr, &maxMutex, done, &stderrMutex)
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
		if orig, found := proxyMap[ok]; found {
			_, _ = os.Stdout.WriteString(orig + "\n")
		} else {
			_, _ = os.Stdout.WriteString(ok + "\n")
		}
	}
}
