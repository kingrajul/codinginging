# mTLS Demo

Two Docker containers demonstrating Mutual TLS (two-way SSL):

| Container | Role | Port |
|-----------|------|------|
| `mtls-server` | Nginx with self-signed certs + `ssl_verify_client on` | `https://localhost:8443` |
| `mtls-client` | Python Flask app — mTLS client + interactive browser UI | `http://localhost:8888` |

## Quick Start

```bash
cd mtls-demo
docker compose up -d
```

`docker compose up` automatically runs `generate-certs` first (Alpine + OpenSSL), which creates the CA, server, and client certificates, then starts the two services.

Open **http://localhost:8888** in your browser.

## What the Demo Covers

| Page | URL | What you see |
|------|-----|--------------|
| Dashboard | `/` | Live status: server reachable, mTLS active, TLS protocol/cipher |
| Handshake | `/handshake` | Step-by-step animated TLS 1.3 mTLS handshake with data payloads |
| Connection Test | `/test` | Fire real requests with and without client cert — see Nginx reject |
| Certificate Viewer | `/certs` | Parsed X.509 fields for CA, server, and client certs + trust chain |
| OpenSSL Trace | `/openssl` | Raw `openssl s_client` output, colorized and annotated |

## Certificate Layout

```
certs/
├── ca/
│   ├── ca.key        Root CA private key (keep offline in production)
│   └── ca.crt        Root CA certificate (10-year validity)
├── server/
│   ├── server.key    Server private key
│   └── server.crt    Server cert — SAN: mtls-server, localhost, 127.0.0.1
└── client/
    ├── client.key    Client private key
    ├── client.crt    Client cert — extKeyUsage=clientAuth
    └── client.p12    PKCS12 bundle for browser import (password: client123)
```

## Try Direct Server Access

The server is also reachable on `https://localhost:8443` directly from your browser. It will **fail** (no client cert in browser) — which is the point:

```bash
# ✅ Works — presents client cert
curl --cert certs/client/client.crt \
     --key  certs/client/client.key \
     --cacert certs/ca/ca.crt \
     https://localhost:8443/

# ❌ Fails — no client cert, TLS alert: certificate_required
curl --cacert certs/ca/ca.crt https://localhost:8443/
```

To access the server from your browser, import `certs/client/client.p12` (password `client123`) into your browser's certificate store, then visit `https://localhost:8443`.

## Stop

```bash
docker compose down
```

To reset certificates: `docker compose down && rm -rf certs/ && docker compose up -d`
