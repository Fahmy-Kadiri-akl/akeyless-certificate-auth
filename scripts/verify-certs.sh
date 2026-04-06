#!/usr/bin/env bash
# ==============================================================================
# Certificate Diagnostic Script for Akeyless Certificate Auth
#
# Validates your CA chain, client certificate, and private key before
# configuring an Akeyless certificate auth method.
#
# Usage:
#   bash verify-certs.sh [ca-chain.pem] [client-cert.pem] [client-key.pem]
# ==============================================================================
set -euo pipefail

CA_CERT="${1:-ca-chain.pem}"
CLIENT_CERT="${2:-client-cert.pem}"
CLIENT_KEY="${3:-client-key.pem}"
PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

echo "=============================================="
echo "  CERTIFICATE DIAGNOSTIC"
echo "=============================================="
echo "  CA cert:     ${CA_CERT}"
echo "  Client cert: ${CLIENT_CERT}"
echo "  Client key:  ${CLIENT_KEY}"
echo "=============================================="
echo ""

# Check files exist
for f in "$CA_CERT" "$CLIENT_CERT" "$CLIENT_KEY"; do
  if [ ! -f "$f" ]; then
    echo "ERROR: File not found: $f"
    exit 1
  fi
done

# 1. CA Certificate details
echo "[1] CA Certificate"
if openssl x509 -in "$CA_CERT" -noout -subject -issuer -dates 2>/dev/null; then
  pass "CA certificate is readable"
else
  fail "Cannot read CA certificate - is it PEM format?"
fi
echo ""

# 2. Client Certificate details
echo "[2] Client Certificate"
if openssl x509 -in "$CLIENT_CERT" -noout -subject -issuer -dates 2>/dev/null; then
  pass "Client certificate is readable"
else
  fail "Cannot read client certificate - is it PEM format?"
fi
echo ""

# 3. Chain verification
echo "[3] Chain Verification"
VERIFY_OUTPUT=$(openssl verify -CAfile "$CA_CERT" "$CLIENT_CERT" 2>&1)
if echo "$VERIFY_OUTPUT" | grep -q ": OK"; then
  pass "Client cert is signed by the CA chain"
else
  fail "Chain verification failed: $VERIFY_OUTPUT"
  echo ""
  echo "  This is the most common cause of 'failed to verify client certificate'"
  echo "  in Akeyless. If you have an intermediate CA, concatenate the chain:"
  echo "    cat intermediate-ca.pem root-ca.pem > ca-chain.pem"
fi
echo ""

# 4. Extended Key Usage
echo "[4] Extended Key Usage (clientAuth)"
EKU=$(openssl x509 -in "$CLIENT_CERT" -noout -ext extendedKeyUsage 2>&1 || true)
if echo "$EKU" | grep -q "Client Authentication"; then
  pass "clientAuth EKU present"
else
  fail "clientAuth EKU missing - Akeyless requires this"
  echo "  Current EKU: ${EKU:-none}"
  echo "  Reissue the cert with clientAuth key usage"
fi
echo ""

# 5. Key match
echo "[5] Private Key Match"
CERT_PUB=$(openssl x509 -in "$CLIENT_CERT" -noout -pubkey 2>/dev/null | openssl dgst -md5)
KEY_PUB=$(openssl pkey -in "$CLIENT_KEY" -pubout 2>/dev/null | openssl dgst -md5)
if [ "$CERT_PUB" = "$KEY_PUB" ]; then
  pass "Private key matches certificate"
else
  fail "Private key does NOT match certificate"
fi
echo ""

# 6. Expiration check
echo "[6] Expiration"
if openssl x509 -in "$CLIENT_CERT" -noout -checkend 0 2>/dev/null; then
  pass "Client certificate is not expired"
  # Check if expiring within 30 days
  if ! openssl x509 -in "$CLIENT_CERT" -noout -checkend 2592000 2>/dev/null; then
    echo "  WARNING: Certificate expires within 30 days"
  fi
else
  fail "Client certificate is expired"
fi

if openssl x509 -in "$CA_CERT" -noout -checkend 0 2>/dev/null; then
  pass "CA certificate is not expired"
else
  fail "CA certificate is expired"
fi
echo ""

# 7. PEM format check
echo "[7] PEM Format"
if head -1 "$CA_CERT" | grep -q "BEGIN CERTIFICATE"; then
  pass "CA cert is PEM format"
else
  fail "CA cert is not PEM format - convert with: openssl x509 -in cert.cer -inform DER -out cert.pem"
fi
if head -1 "$CLIENT_CERT" | grep -q "BEGIN CERTIFICATE"; then
  pass "Client cert is PEM format"
else
  fail "Client cert is not PEM format"
fi
echo ""

# Summary
echo "=============================================="
echo "  RESULTS"
echo "=============================================="
echo "  Passed: ${PASS}"
echo "  Failed: ${FAIL}"
echo "=============================================="

if [ "$FAIL" -eq 0 ]; then
  echo ""
  echo "  All checks passed. Safe to create the Akeyless cert auth method."
  echo ""
  echo "  Next step:"
  echo "    akeyless create-auth-method-cert \\"
  echo "      --name \"/Auth/CertificateAuth\" \\"
  echo "      --unique-identifier common_name \\"
  echo "      --certificate-data \"\$(base64 -w0 ${CA_CERT})\""
  echo ""
  exit 0
else
  echo ""
  echo "  Fix the failures above before configuring Akeyless."
  echo ""
  exit 1
fi
