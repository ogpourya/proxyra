package xray

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"net"
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
	return "", fmt.Errorf("xray binary not found in PATH")
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
