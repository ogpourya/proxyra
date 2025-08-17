package main

import (
	"strconv"
	"bufio"
	"bytes"
	"context"
	"flag"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	readLimitBytes = 64 * 1024 // read up to 64 KB from curl stdout
	maxLineBytes   = 1024 * 1024
)

func readProxiesFromStdin() ([]string, error) {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return nil, err
	}
	// if stdin is a terminal, skip
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

func checkProxy(proxyAddr, target string, timeout int, re *regexp.Regexp) bool {
	// hard timeout via context
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	// curl options:
	// -x proxy, --max-time, -s silent, -L follow redirects, -k ignore cert errors
	cmd := exec.CommandContext(ctx, "curl",
		"-x", proxyAddr,
		"--max-time", strconv.Itoa(timeout),
		"-s",
		"-L",
		"-k",
		target,
	)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return false
	}

	if err := cmd.Start(); err != nil {
		return false
	}

	// read up to readLimitBytes in a goroutine
	var buf bytes.Buffer
	done := make(chan struct{})
	go func() {
		// try to copy up to readLimitBytes
		_, _ = io.CopyN(&buf, stdout, int64(readLimitBytes))
		close(done)
	}()

	// wait either for read to finish or context timeout
	select {
	case <-done:
		// read finished because we hit the limit or curl closed stdout
	case <-ctx.Done():
		// timeout fired, ensure process is killed
		_ = cmd.Process.Kill()
		// wait for goroutine to return
		<-done
	}

	// if buffer reached the limit, kill the process to avoid it blocking on writes
	if buf.Len() >= readLimitBytes {
		_ = cmd.Process.Kill()
	}

	// wait for process to exit; ignore errors and do not print
	_ = cmd.Wait()

	// apply regex match on what we read
	return re.Match(buf.Bytes())
}

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
	timeout := flag.Int("timeout", 5, "Timeout in seconds (required)")
	threads := flag.Int("threads", 10, "Number of concurrent threads (required)")
	listFile := flag.String("list", "", "File with list of proxies")
	regexStr := flag.String("regex", ".*", "Regex to match response (required)")
	flag.Parse()

	// silent exit on bad usage or missing values
	if *target == "" || *timeout <= 0 || *threads <= 0 || *regexStr == "" {
		os.Exit(1)
	}

	// ensure curl exists
	if _, err := exec.LookPath("curl"); err != nil {
		os.Exit(1)
	}

	re, err := regexp.Compile(*regexStr)
	if err != nil {
		os.Exit(1)
	}

	proxies, err := readProxiesFromStdin()
	if err != nil {
		os.Exit(1)
	}
	if len(proxies) == 0 && *listFile != "" {
		proxies, err = readProxiesFromFile(*listFile)
		if err != nil {
			os.Exit(1)
		}
	}
	if len(proxies) == 0 {
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

	// print only working proxies, nothing else
	for ok := range out {
		_, _ = os.Stdout.WriteString(ok + "\n")
	}
}
