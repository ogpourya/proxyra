# proxyra
proxyra — Fast, minimal, reliable proxy checker.

## Features
- Minimal memory usage (reads only up to 64KB per response)
- Removes duplicate proxies automatically
- Regex matching for full response (Headers + Body)
- Supports all common proxy types: HTTP, HTTPS, SOCKS4, SOCKS5
- Supports fractional timeouts (e.g., 0.5s)
- Supports custom headers and status code validation
- TCP connection mode support
- Option to ignore SSL certificate errors

## Options

| Option | Description                               |
| ------ | ----------------------------------------- |
| `-u`   | Target URL to check                       |
| `-t`   | Timeout in seconds (e.g. 5 or 0.5)        |
| `-c`   | Concurrency (number of threads)           |
| `-l`   | File containing list of proxies           |
| `-r`   | Regex to match response (Headers or Body) |
| `-k`   | Allow insecure TLS connections            |
| `-n`   | Number of times a proxy must pass checks  |
| `-m`   | Stop after finding N valid proxies        |
| `-s`   | Expected HTTP status code                 |
| `-H`   | Custom request header (can be repeated)   |
| `-tcp` | TCP connection mode                       |

## Installation

```bash
GOPROXY=direct go install github.com/ogpourya/proxyra@latest
```

## Usage Examples

Pipe a list of proxies:

```bash
cat proxies.txt | proxyra -u https://example.com -t 5 -c 20 -r "Example Domain"
```

Use a file directly:

```bash
proxyra -u https://example.com -t 5 -c 20 -l proxies.txt -r "Example Domain"
```

## License

MIT License
