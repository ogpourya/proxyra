# proxyra
Fast, minimal, and reliable proxy checker with automatic multi-source IP validation.

## Features
- **Smart Mode**: Automatic anonymity & functionality check via multi-source IP matching.
- **Protocol Support**: HTTP, HTTPS, SOCKS4, SOCKS4a, SOCKS5.
- **TCP Mode**: Raw connection testing for non-HTTP targets.
- **Validation**: Regex matching on full response (Headers + Body) and Status Code checks.
- **Efficient**: Minimal memory footprint; processes only up to 64KB per response.
- **Parallel**: High-performance concurrency with fractional timeout support.

## Smart Mode (Default)
If `-u` or `-r` are omitted, **proxyra** validates proxies by sequentially checking their reported IP against:
1. `icanhazip.com`
2. `checkip.amazonaws.com`
3. `a.ident.me`

## Options
| Option | Description |
| :--- | :--- |
| `-u` | Target URL (HTTP) or host:port (TCP) |
| `-t` | Timeout in seconds (default: 5, supports decimals like 0.5) |
| `-c` | Concurrency/Threads (default: 10) |
| `-l` | Path to proxy list file |
| `-r` | Regex to match in response headers or body |
| `-s` | Expected HTTP status code (e.g., 200) |
| `-n` | Number of successful passes required (default: 1) |
| `-m` | Stop after finding N valid proxies |
| `-H` | Custom header (e.g., `-H "User-Agent: bot"`) |
| `-k` | Allow insecure TLS (default: false) |
| `-tcp`| Enable raw TCP connection mode |

## Installation
```bash
go install github.com/ogpourya/proxyra@latest
```

## Examples

### 1. Smart Anonymity Check (Fastest)
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

## License
MIT
