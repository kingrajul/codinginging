# Security Headers Demo

An educational Nginx/Docker site that demonstrates 6 common HTTP security header vulnerabilities.

## Quick Start

```bash
cd security-headers-demo
docker compose up -d
```

Open **http://localhost:8080** in your browser.

To stop: `docker compose down`

## What's Included

| Page | Missing Header | Attack Demonstrated |
|------|---------------|---------------------|
| `csp-xss.html` | `Content-Security-Policy` | Reflected XSS — live injectable demo |
| `clickjacking.html` | `X-Frame-Options` | Hidden iframe UI overlay attack |
| `mime-sniffing.html` | `X-Content-Type-Options` | Polyglot file / MIME type confusion |
| `hsts.html` | `Strict-Transport-Security` | SSL stripping with sslstrip walkthrough |
| `referrer-leak.html` | `Referrer-Policy` | Token/session leakage via Referer header |
| `permissions-policy.html` | `Permissions-Policy` | Camera / mic / geolocation abuse |

## Verify There Are No Security Headers

Open DevTools → Network tab → reload the page → select any document request → inspect **Response Headers**.
You will see no `Content-Security-Policy`, `X-Frame-Options`, `Strict-Transport-Security`, etc.

## For Educational Use Only

Do **not** deploy `nginx/nginx.conf` in production. It is intentionally stripped of all protective headers.
