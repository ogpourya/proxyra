# proxyra
Fast, minimal, and reliable proxy checker with automatic multi-source IP validation and native Xray subscription support.

## Features
- **Smart Mode** — Automatic anonymity & functionality check via multi-source IP matching.
- **Protocol Support** — HTTP, HTTPS, SOCKS4, SOCKS4a, SOCKS5.
- **Xray Integration** — Auto-detect and parse VLESS, VMess, Trojan, Shadowsocks, Hysteria2, and WireGuard links; spins up local xray instances as SOCKS5 proxies for validation.
- **TCP Mode** — Raw connection testing for non-HTTP targets (CONNECT for HTTP proxies, direct dial for SOCKS proxies).
- **Validation** — Regex matching on full response (Headers + Body) and Status Code checks.
- **Efficient** — Minimal memory footprint; processes only up to 64KB per response.
- **Parallel** — High-performance concurrency with fractional timeout support.
- **Deduplication** — Duplicate proxy entries are silently removed.

## Smart Mode (Default)
If `-u` is omitted, **proxyra** validates proxies by sequentially checking their reported IP against:
1. `icanhazip.com`
2. `checkip.amazonaws.com`
3. `a.ident.me`

A proxy passes if its IP matches in response from any of these services.

## Xray Links
When a proxy entry starts with `vless://`, `vmess://`, `trojan://`, `ss://`, `hysteria2://`, `hy2://`, `wireguard://`, or `wg://`, proxyra automatically parses the link, starts a local xray instance, and validates it as a `socks5://127.0.0.1:<port>` outbound. The original link is printed on success.

The xray binary must be installed and available in `$PATH` (or at `/usr/local/bin/xray` / `/usr/bin/xray`).

## Options
| Option | Description |
| :--- | :--- |
| `-u` | Target URL (`http://...`) or host:port (with `-tcp`) |
| `-t` | Timeout in seconds (float, e.g. `0.5`; default: `5`) |
| `-c` | Concurrency / goroutines (default: `10`) |
| `-l` | Path to proxy list file |
| `-r` | Regex to match in response headers or body |
| `-s` | Expected HTTP status code (e.g., `200`; `0` = any) |
| `-n` | Number of consecutive passes required (default: `1`) |
| `-m` | Stop after finding N valid proxies (`0` = unlimited) |
| `-H` | Custom request header, repeatable (`-H "Key: Value"`) |
| `-k` | Allow insecure TLS connections (default: `false`) |
| `-tcp`| Enable raw TCP connection mode |

## Installation
```bash
go install github.com/ogpourya/proxyra@latest
```

Proxyra expects the [xray](https://github.com/XTLS/Xray-core) binary in `$PATH` when validating xray subscription links.

## Examples

### 1. Smart Anonymity Check
```bash
cat proxies.txt | proxyra -c 50 -t 2
```

### 2. Validate against specific site
```bash
proxyra -l list.txt -u https://google.com -r "Google Search" -s 200
```

### 3. High-Speed SOCKS5 Validation
```bash
cat socks5.txt | proxyra -t 0.8 -c 100 -m 10
```

### 4. Custom Headers & TCP Mode
```bash
# HTTP with custom headers
proxyra -l list.txt -u http://api.com -H "Auth: secret"

# Raw TCP check
proxyra -l list.txt -tcp -u 1.1.1.1:53
```

### 5. Xray Subscription Links
```bash
# Mixed list with regular proxies and xray links
cat nodes.txt | proxyra -t 3 -c 20 -m 5
```
Where `nodes.txt` contains any combination of `socks5://...`, `http://...`, `vless://...`, `vmess://...`, `trojan://...`, `ss://...`, `hysteria2://...`, etc.

## License
MIT
