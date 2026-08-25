package xray

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Instance struct {
	Port int
	Tag  string
}

type entry struct {
	outbound *XrayOutbound
	port     int
	tag      string
}

type Manager struct {
	mu      sync.Mutex
	binPath string
	tmpDir  string
	entries []*entry
	cmd     *exec.Cmd
	done    chan struct{}
}

func NewManager() *Manager {
	return &Manager{}
}

func (m *Manager) findXrayBin() (string, error) {
	if m.binPath != "" {
		return m.binPath, nil
	}
	paths := []string{"xray", "/usr/local/bin/xray", "/usr/bin/xray"}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			m.binPath = p
			return p, nil
		}
		if path, err := exec.LookPath(p); err == nil {
			m.binPath = path
			return path, nil
		}
	}

	cacheDir := filepath.Join(os.Getenv("HOME"), ".local", "bin")
	cachePath := filepath.Join(cacheDir, "xray")
	if info, err := os.Stat(cachePath); err == nil && info.Mode().Perm()&0111 != 0 {
		m.binPath = cachePath
		return cachePath, nil
	}

	return m.downloadXray()
}

func (m *Manager) downloadXray() (string, error) {
	binDir := filepath.Join(os.Getenv("HOME"), ".local", "bin")
	if err := os.MkdirAll(binDir, 0755); err != nil {
		return "", fmt.Errorf("create %s: %w", binDir, err)
	}
	target := filepath.Join(binDir, "xray")

	version, err := fetchLatestXrayVersion()
	if err != nil {
		return "", fmt.Errorf("fetch latest xray version: %w", err)
	}

	archStr, err := detectArch()
	if err != nil {
		return "", err
	}

	url := fmt.Sprintf("https://github.com/XTLS/Xray-core/releases/download/%s/Xray-linux-%s.zip",
		version, archStr)

	fmt.Fprintf(os.Stderr, "Downloading xray %s (linux-%s)...\n", version, archStr)

	tmpZip := target + ".zip"
	if err := httpDownloadFile(url, tmpZip); err != nil {
		os.Remove(tmpZip)
		return "", fmt.Errorf("download xray: %w", err)
	}
	defer os.Remove(tmpZip)

	dgstURL := url + ".dgst"
	if err := verifySHA256(tmpZip, dgstURL); err != nil {
		os.Remove(tmpZip)
		return "", fmt.Errorf("verify xray zip: %w", err)
	}

	if err := unzipXray(tmpZip, target); err != nil {
		return "", fmt.Errorf("extract xray: %w", err)
	}

	if err := os.Chmod(target, 0755); err != nil {
		return "", fmt.Errorf("chmod xray: %w", err)
	}

	for _, dat := range []string{"geosite.dat", "geoip.dat"} {
		datURL := fmt.Sprintf("https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/%s", dat)
		datPath := filepath.Join(binDir, dat)
		if err := httpDownloadFile(datURL, datPath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to download %s: %v\n", dat, err)
			continue
		}
		if err := verifySHA256(datPath, datURL+".sha256sum"); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to verify %s: %v\n", dat, err)
			os.Remove(datPath)
		}
	}

	m.binPath = target
	fmt.Fprintf(os.Stderr, "xray installed to %s\n", target)
	return target, nil
}

func verifySHA256(filePath, dgstURL string) error {
	resp, err := http.Get(dgstURL)
	if err != nil {
		return fmt.Errorf("fetch dgst: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("fetch dgst: http %s", resp.Status)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read dgst: %w", err)
	}
	expected := ""
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(strings.ToUpper(line), "SHA2-256=") || strings.HasPrefix(strings.ToUpper(line), "SHA256=") || strings.HasPrefix(strings.ToUpper(line), "SHA2=") {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				expected = strings.TrimSpace(parts[1])
				break
			}
		}
	}
	if expected == "" {
		parts := strings.Fields(string(body))
		if len(parts) > 0 {
			expected = parts[0]
		}
	}
	if expected == "" {
		return fmt.Errorf("no sha256 found in dgst file")
	}
	f, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if !strings.EqualFold(sum, expected) {
		return fmt.Errorf("sha256 mismatch: got %s, want %s", sum, expected)
	}
	return nil
}

func fetchLatestXrayVersion() (string, error) {
	req, err := http.NewRequest("GET", "https://api.github.com/repos/XTLS/Xray-core/releases/latest", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("github api: %s", resp.Status)
	}
	var release struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return "", err
	}
	if release.TagName == "" {
		return "", fmt.Errorf("empty tag_name")
	}
	return release.TagName, nil
}

func httpDownloadFile(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("http %s", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(f, resp.Body)
	return err
}

func unzipXray(zipPath, dest string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		if filepath.Base(f.Name) == "xray" {
			rc, err := f.Open()
			if err != nil {
				return err
			}
			out, err := os.Create(dest)
			if err != nil {
				rc.Close()
				return err
			}
			_, err = io.Copy(out, rc)
			out.Close()
			rc.Close()
			return err
		}
	}
	return fmt.Errorf("xray binary not found in zip")
}

func detectArch() (string, error) {
	uname, err := exec.Command("uname", "-m").Output()
	if err != nil {
		return "", fmt.Errorf("uname -m: %w", err)
	}
	switch strings.TrimSpace(string(uname)) {
	case "i386", "i686":
		return "32", nil
	case "amd64", "x86_64":
		return "64", nil
	case "armv5tel":
		return "arm32-v5", nil
	case "armv6l":
		buf, _ := os.ReadFile("/proc/cpuinfo")
		if strings.Contains(string(buf), "vfp") {
			return "arm32-v6", nil
		}
		return "arm32-v5", nil
	case "armv7", "armv7l":
		buf, _ := os.ReadFile("/proc/cpuinfo")
		if !strings.Contains(string(buf), "vfp") {
			return "arm32-v5", nil
		}
		return "arm32-v7a", nil
	case "armv8", "aarch64":
		return "arm64-v8a", nil
	case "mips":
		return "mips32", nil
	case "mipsle":
		return "mips32le", nil
	case "mips64":
		buf, _ := os.ReadFile("/proc/cpuinfo")
		if strings.Contains(string(buf), "Little Endian") {
			return "mips64le", nil
		}
		return "mips64", nil
	case "mips64le":
		return "mips64le", nil
	case "ppc64":
		return "ppc64", nil
	case "ppc64le":
		return "ppc64le", nil
	case "riscv64":
		return "riscv64", nil
	case "s390x":
		return "s390x", nil
	default:
		return "", fmt.Errorf("unsupported arch: %s", strings.TrimSpace(string(uname)))
	}
}

func (m *Manager) AddOutbound(ob *XrayOutbound) (*Instance, error) {
	port, err := findFreePort()
	if err != nil {
		return nil, err
	}
	tag := ob.Tag
	if tag == "" {
		tag = fmt.Sprintf("xray-%d", port)
	}
	m.mu.Lock()
	m.entries = append(m.entries, &entry{outbound: ob, port: port, tag: tag})
	m.mu.Unlock()
	return &Instance{Port: port, Tag: tag}, nil
}

func (m *Manager) Start() error {
	m.mu.Lock()
	if len(m.entries) == 0 {
		m.mu.Unlock()
		return nil
	}
	entries := make([]*entry, len(m.entries))
	copy(entries, m.entries)
	m.mu.Unlock()

	bin, err := m.findXrayBin()
	if err != nil {
		return err
	}

	tmpDir, err := os.MkdirTemp("", "proxyra-xray-*")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	configPath := filepath.Join(tmpDir, "config.json")

	config := buildConfig(entries)

	configJSON, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		os.RemoveAll(tmpDir)
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(configPath, configJSON, 0644); err != nil {
		os.RemoveAll(tmpDir)
		return fmt.Errorf("write config: %w", err)
	}

	stderr := new(strings.Builder)
	done := make(chan struct{})
	cmd := exec.Command(bin, "-c", configPath)
	cmd.Stdout = nil
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		os.RemoveAll(tmpDir)
		return fmt.Errorf("start xray: %w", err)
	}

	go func() {
		cmd.Wait()
		close(done)
	}()

	ports := make([]int, len(entries))
	for i, e := range entries {
		ports[i] = e.port
	}
	if err := waitForPorts(ports, done, 30*time.Second); err != nil {
		cmd.Process.Kill()
		<-done
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			err = fmt.Errorf("%v\nxray stderr: %s", err, msg)
		}
		os.RemoveAll(tmpDir)
		return err
	}

	m.mu.Lock()
	m.tmpDir = tmpDir
	m.cmd = cmd
	m.done = done
	m.mu.Unlock()

	return nil
}

func (m *Manager) Instances() []*Instance {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Instance, len(m.entries))
	for i, e := range m.entries {
		out[i] = &Instance{Port: e.port, Tag: e.tag}
	}
	return out
}

func (m *Manager) StopAll() {
	m.mu.Lock()
	cmd := m.cmd
	done := m.done
	tmpDir := m.tmpDir
	m.mu.Unlock()

	if cmd != nil && cmd.Process != nil {
		cmd.Process.Kill()
	}
	if done != nil {
		<-done
	}
	if tmpDir != "" {
		os.RemoveAll(tmpDir)
	}
}

func buildConfig(entries []*entry) map[string]any {
	inbounds := make([]any, 0, len(entries))
	outbounds := make([]any, 0, len(entries)+1)
	rules := make([]any, 0, len(entries))

	for _, e := range entries {
		tag := fmt.Sprintf("%s-%d", slugTag(e.tag), e.port)
		inbounds = append(inbounds, map[string]any{
			"tag":      fmt.Sprintf("socks5-%s", tag),
			"port":     e.port,
			"listen":   "127.0.0.1",
			"protocol": "socks",
			"settings": map[string]any{
				"udp":  true,
				"auth": "noauth",
			},
			"sniffing": map[string]any{
				"enabled":      true,
				"destOverride": []string{"http", "tls"},
			},
		})

		outbounds = append(outbounds, configToRaw(e.outbound, tag))

		rules = append(rules, map[string]any{
			"type":        "field",
			"inboundTag":  []string{fmt.Sprintf("socks5-%s", tag)},
			"outboundTag": tag,
		})
	}

	outbounds = append(outbounds, map[string]any{
		"protocol": "dns",
		"tag":      "dns-outbound",
	})

	return map[string]any{
		"log": map[string]any{
			"loglevel": "none",
		},
		"dns": map[string]any{
			"servers": []any{
				"https+local://1.1.1.1/dns-query",
				"https+local://1.0.0.1/dns-query",
				"localhost",
			},
			"queryStrategy": "UseIP",
			"disableCache":  false,
			"tag":           "dns-outbound",
		},
		"inbounds":  inbounds,
		"outbounds": outbounds,
		"routing": map[string]any{
			"domainStrategy": "IPOnDemand",
			"rules":          rules,
		},
	}
}

func configToRaw(ob *XrayOutbound, tag string) map[string]any {
	raw := map[string]any{
		"protocol": ob.Protocol,
		"tag":      tag,
		"settings": ob.Settings,
	}
	if ob.StreamSettings != nil {
		raw["streamSettings"] = ob.StreamSettings
	}
	return raw
}

func findFreePort() (int, error) {
	for i := 0; i < 10; i++ {
		port := 30000 + rand.N(20000)
		ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
		if err == nil {
			ln.Close()
			return port, nil
		}
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port, nil
}

func waitForPorts(ports []int, done <-chan struct{}, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	remaining := make(map[int]struct{})
	for _, p := range ports {
		remaining[p] = struct{}{}
	}
	var mu sync.Mutex
	for len(remaining) > 0 {
		select {
		case <-done:
			return fmt.Errorf("xray process exited unexpectedly")
		default:
		}
		if time.Now().After(deadline) {
			var unready []int
			for p := range remaining {
				unready = append(unready, p)
			}
			return fmt.Errorf("timeout waiting for ports: %v", unready)
		}

		mu.Lock()
		check := make([]int, 0, len(remaining))
		for p := range remaining {
			check = append(check, p)
		}
		mu.Unlock()

		var wg sync.WaitGroup
		for _, port := range check {
			wg.Add(1)
			go func(port int) {
				defer wg.Done()
				conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 100*time.Millisecond)
				if err == nil {
					conn.Close()
					mu.Lock()
					delete(remaining, port)
					mu.Unlock()
				}
			}(port)
		}
		wg.Wait()
		if len(remaining) > 0 {
			time.Sleep(20 * time.Millisecond)
		}
	}
	return nil
}

func slugTag(tag string) string {
	if tag == "" {
		return "xray"
	}
	s := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
			return r
		}
		return '-'
	}, tag)
	for strings.Contains(s, "--") {
		s = strings.ReplaceAll(s, "--", "-")
	}
	s = strings.Trim(s, "-")
	if s == "" {
		return "xray"
	}
	return s
}
