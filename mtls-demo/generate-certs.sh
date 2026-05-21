#!/bin/sh
# Generate all certificates for the mTLS demo.
# Run via:  docker compose run generate-certs
# Or directly with openssl on the host.
set -e

OUT="${CERTS_DIR:-certs}"
mkdir -p "$OUT/ca" "$OUT/server" "$OUT/client"

# Skip if certs already exist
if [ -f "$OUT/ca/ca.crt" ] && [ -f "$OUT/client/client.crt" ] && [ -f "$OUT/server/server.crt" ]; then
  echo "Certificates already present — skipping generation."
  exit 0
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  mTLS Demo — Certificate Generator"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── 1. Root Certificate Authority ────────────────────────────────────────────
echo "[1/3] Generating Root CA..."
openssl genrsa -out "$OUT/ca/ca.key" 4096 2>/dev/null
openssl req -new -x509 -days 3650 \
  -key "$OUT/ca/ca.key" \
  -out "$OUT/ca/ca.crt" \
  -subj "/C=US/ST=Demo/L=DemoCity/O=mTLS Demo/OU=Certificate Authority/CN=mTLS Demo Root CA"
echo "  ✓  $OUT/ca/ca.crt  (valid 10 years)"

# ── 2. Server Certificate ─────────────────────────────────────────────────────
echo "[2/3] Generating Server Certificate..."
openssl genrsa -out "$OUT/server/server.key" 2048 2>/dev/null
openssl req -new \
  -key "$OUT/server/server.key" \
  -out "$OUT/server/server.csr" \
  -subj "/C=US/ST=Demo/L=DemoCity/O=mTLS Demo/OU=Server/CN=mtls-server"

cat > "$OUT/server/v3.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:mtls-server,DNS:localhost,IP:127.0.0.1
EOF

openssl x509 -req -days 365 \
  -in "$OUT/server/server.csr" \
  -CA "$OUT/ca/ca.crt" \
  -CAkey "$OUT/ca/ca.key" \
  -CAcreateserial \
  -extfile "$OUT/server/v3.ext" \
  -out "$OUT/server/server.crt" 2>/dev/null
echo "  ✓  $OUT/server/server.crt  (SAN: mtls-server, localhost)"

# ── 3. Client Certificate ─────────────────────────────────────────────────────
echo "[3/3] Generating Client Certificate..."
openssl genrsa -out "$OUT/client/client.key" 2048 2>/dev/null
openssl req -new \
  -key "$OUT/client/client.key" \
  -out "$OUT/client/client.csr" \
  -subj "/C=US/ST=Demo/L=DemoCity/O=mTLS Demo/OU=Client/CN=demo-client/emailAddress=client@mtls.demo"

cat > "$OUT/client/v3.ext" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=clientAuth
EOF

openssl x509 -req -days 365 \
  -in "$OUT/client/client.csr" \
  -CA "$OUT/ca/ca.crt" \
  -CAkey "$OUT/ca/ca.key" \
  -CAcreateserial \
  -extfile "$OUT/client/v3.ext" \
  -out "$OUT/client/client.crt" 2>/dev/null
echo "  ✓  $OUT/client/client.crt  (extendedKeyUsage=clientAuth)"

# PKCS12 bundle so you can import the client cert into a browser
openssl pkcs12 -export \
  -out "$OUT/client/client.p12" \
  -inkey "$OUT/client/client.key" \
  -in "$OUT/client/client.crt" \
  -certfile "$OUT/ca/ca.crt" \
  -passout pass:client123 2>/dev/null || true
echo "  ✓  $OUT/client/client.p12  (browser import, password: client123)"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Done! Run:  docker compose up -d"
echo "  Then open: http://localhost:8888"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
