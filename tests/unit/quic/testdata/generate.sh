#!/bin/bash
#
# Generates the certificates used by the unit tests of scion_quic (tests/unit/quic/test_quic.c).
#
# Files (all keys EC P-256, signatures ECDSA with SHA-256, valid for 100 years):
#   ca.pem        self-signed test CA "csnet test CA"; the client trusts it in the verification tests
#   server.pem    server certificate CN=quic.test, SAN DNS:quic.test, signed by ca.pem; the test server presents it
#   server.key    private key of server.pem; the test server signs the TLS handshake with it
#   other_ca.pem  second, unrelated self-signed CA "other test CA" that signed nothing; the client trusts only this one
#                 in test_quic_rejects_an_untrusted_certificate
#
# The tests compare against the name in QUIC_TEST_SERVER_NAME (quic_test_server.h), so keep SERVER_NAME in sync.
# The private keys of the CAs are not needed by the tests and are discarded. The certificates are test data only.
#
# Usage: ./generate.sh [output directory]   (default: the directory of this script)
# Requires OpenSSL >= 1.1.1. Run the unit tests afterwards (unit_tests, built with -DBUILD_QUIC=ON -DBUILD_TESTS=ON).

set -euo pipefail

OUT_DIR="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
SERVER_NAME="quic.test"
DAYS=36500

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

mkdir -p "$OUT_DIR"

# Self-signed CA certificate: generate_ca <common name> <certificate file> <key file>
generate_ca() {
	openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -sha256 -days "$DAYS" \
		-subj "/CN=$1" \
		-addext "basicConstraints=critical,CA:TRUE" \
		-addext "keyUsage=critical,keyCertSign" \
		-keyout "$3" -out "$2" 2>/dev/null
}

generate_ca "csnet test CA" "$OUT_DIR/ca.pem" "$TMP_DIR/ca.key"
generate_ca "other test CA" "$OUT_DIR/other_ca.pem" "$TMP_DIR/other_ca.key"

# Server key (PKCS#8 PEM, readable by OpenSSL and mbedTLS) and certificate signed by the test CA.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 -out "$OUT_DIR/server.key"
openssl req -new -key "$OUT_DIR/server.key" -subj "/CN=$SERVER_NAME" -out "$TMP_DIR/server.csr"
cat > "$TMP_DIR/server.ext" <<EOF
basicConstraints=CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
subjectAltName=DNS:$SERVER_NAME
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid
EOF
openssl x509 -req -in "$TMP_DIR/server.csr" -CA "$OUT_DIR/ca.pem" -CAkey "$TMP_DIR/ca.key" -set_serial "0x$(openssl rand -hex 16)" \
	-sha256 -days "$DAYS" -extfile "$TMP_DIR/server.ext" -out "$OUT_DIR/server.pem" 2>/dev/null

echo "Generated ca.pem, other_ca.pem, server.pem and server.key in $OUT_DIR"
