#!/usr/bin/env bash
set -euo pipefail
umask 077

OPENSSL_BIN="${OPENSSL_BIN:-openssl}"
TLS_DIR="${TLS_DIR:-chapter-12/tls}"

if ! command -v "$OPENSSL_BIN" >/dev/null 2>&1; then
  printf 'OpenSSL was not found. Set OPENSSL_BIN or install OpenSSL.\n' >&2
  exit 1
fi

mkdir -p "$TLS_DIR"
for file in ca.key ca.crt ca-ext.cnf server.key server.csr server.crt server.pem \
  server-ext.cnf client.key client.csr client.crt client.pem client-ext.cnf; do
  if [[ -e "$TLS_DIR/$file" ]]; then
    printf 'Refusing to overwrite %s. Choose a new TLS_DIR or move the existing files.\n' \
      "$TLS_DIR/$file" >&2
    exit 1
  fi
done

cat > "$TLS_DIR/ca-ext.cnf" <<'OPENSSL_CONFIG'
[req]
distinguished_name = dn
prompt = no

[dn]
CN = MongoDB-Lab-CA

[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
OPENSSL_CONFIG
cat > "$TLS_DIR/server-ext.cnf" <<'OPENSSL_CONFIG'
[server_ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
OPENSSL_CONFIG
cat > "$TLS_DIR/client-ext.cnf" <<'OPENSSL_CONFIG'
[client_ext]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
OPENSSL_CONFIG

"$OPENSSL_BIN" genrsa -out "$TLS_DIR/ca.key" 4096
"$OPENSSL_BIN" req -new -x509 -sha256 -days 365 \
  -key "$TLS_DIR/ca.key" -out "$TLS_DIR/ca.crt" \
  -subj "/CN=MongoDB-Lab-CA" -config "$TLS_DIR/ca-ext.cnf" \
  -extensions v3_ca
"$OPENSSL_BIN" genrsa -out "$TLS_DIR/server.key" 4096
"$OPENSSL_BIN" req -new -sha256 -key "$TLS_DIR/server.key" \
  -out "$TLS_DIR/server.csr" -subj "/CN=localhost"
"$OPENSSL_BIN" x509 -req -sha256 -days 365 \
  -in "$TLS_DIR/server.csr" -CA "$TLS_DIR/ca.crt" \
  -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
  -out "$TLS_DIR/server.crt" \
  -extfile "$TLS_DIR/server-ext.cnf" -extensions server_ext
cat "$TLS_DIR/server.key" "$TLS_DIR/server.crt" > "$TLS_DIR/server.pem"
"$OPENSSL_BIN" genrsa -out "$TLS_DIR/client.key" 4096
"$OPENSSL_BIN" req -new -sha256 -key "$TLS_DIR/client.key" \
  -out "$TLS_DIR/client.csr" -subj "/CN=mongo-lab-client"
"$OPENSSL_BIN" x509 -req -sha256 -days 365 \
  -in "$TLS_DIR/client.csr" -CA "$TLS_DIR/ca.crt" \
  -CAkey "$TLS_DIR/ca.key" -CAcreateserial \
  -out "$TLS_DIR/client.crt" \
  -extfile "$TLS_DIR/client-ext.cnf" -extensions client_ext
cat "$TLS_DIR/client.key" "$TLS_DIR/client.crt" > "$TLS_DIR/client.pem"

printf '\n[OK] Generated the local CA and localhost server certificate.\n'
printf 'Start MongoDB in another terminal with:\n\n'
printf 'mongod --tlsMode requireTLS --tlsCertificateKeyFile "%s/server.pem" ' "$TLS_DIR"
printf -- '--tlsCAFile "%s/ca.crt" --tlsAllowConnectionsWithoutCertificates ' "$TLS_DIR"
printf '%s\n' '--bind_ip 127.0.0.1 --port 27017'
printf '\nUse %s/ca.crt to verify the server certificate and %s/client.pem for PyMongo.\n' \
  "$TLS_DIR" "$TLS_DIR"
printf 'Keep all private keys and combined PEM files private.\n'
