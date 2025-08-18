# proxyra
proxyra — Fast, minimal, reliable proxy checker.

## Features
- Minimal memory usage (reads only up to 64KB per response)
- Removes duplicate proxies automatically
- Regex matching for response content
- Ignores SSL certificate errors
- Supports all common proxy types: HTTP, HTTPS, SOCKS4, SOCKS5

## Options

| Option     | Description                         | Required |
|------------|-------------------------------------|----------|
| `-url`     | Target URL to check                  | Yes      |
| `-timeout` | Timeout in seconds                   | Yes      |
| `-threads` | Number of concurrent threads        | Yes      |
| `-list`    | File containing list of proxies     | No       |
| `-regex`   | Regex to match response content     | Yes      |

## Installation

```bash
GOPROXY=direct go install github.com/pzaeemfar/proxyra@latest
````

## Usage Examples

Pipe a list of proxies:

```bash
cat proxies.txt | proxyra -url https://example.com -timeout 5 -threads 20 -regex "Example Domain"
```

Use a file directly:

```bash
proxyra -url https://example.com -timeout 5 -threads 20 -list proxies.txt -regex "Example Domain"
```

## License

MIT License
