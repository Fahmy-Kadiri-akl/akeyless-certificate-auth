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
WARN=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }
warn() { echo "  WARN: $1"; WARN=$((WARN + 1)); }

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

# ---------------------------------------------------------------------------
# 1. PEM format and encoding checks
# ---------------------------------------------------------------------------
echo "[1] PEM Format and Encoding"

# Check for PKCS7 wrapper (common with enterprise CA .p7b exports)
if head -1 "$CA_CERT" | grep -q "BEGIN PKCS7"; then
  fail "CA cert is PKCS7 format, not PEM. Extract certificates with:"
  echo "       openssl pkcs7 -in ${CA_CERT} -print_certs -out ca-chain-fixed.pem"
elif head -1 "$CA_CERT" | grep -q "BEGIN CERTIFICATE"; then
  pass "CA cert is PEM format"
else
  # Check if it's DER (binary)
  if openssl x509 -in "$CA_CERT" -inform DER -noout 2>/dev/null; then
    fail "CA cert is DER format, not PEM. Convert with:"
    echo "       openssl x509 -in ${CA_CERT} -inform DER -out ca-cert.pem -outform PEM"
  else
    fail "CA cert is not a recognized certificate format (not PEM, DER, or PKCS7)"
  fi
fi

if head -1 "$CLIENT_CERT" | grep -q "BEGIN CERTIFICATE"; then
  pass "Client cert is PEM format"
else
  if openssl x509 -in "$CLIENT_CERT" -inform DER -noout 2>/dev/null; then
    fail "Client cert is DER format, not PEM. Convert with:"
    echo "       openssl x509 -in ${CLIENT_CERT} -inform DER -out client-cert.pem -outform PEM"
  else
    fail "Client cert is not a recognized certificate format"
  fi
fi

# Check for Windows CRLF line endings
if grep -Pq '\r$' "$CA_CERT" 2>/dev/null; then
  fail "CA cert has Windows line endings (CRLF). Fix with:"
  echo "       sed -i 's/\\r\$//' ${CA_CERT}"
  echo "       (or: dos2unix ${CA_CERT})"
fi
if grep -Pq '\r$' "$CLIENT_CERT" 2>/dev/null; then
  fail "Client cert has Windows line endings (CRLF). Fix with:"
  echo "       sed -i 's/\\r\$//' ${CLIENT_CERT}"
fi

# Check for extraneous text before BEGIN CERTIFICATE
FIRST_LINE=$(head -1 "$CA_CERT")
if [ "$FIRST_LINE" != "-----BEGIN CERTIFICATE-----" ] && ! echo "$FIRST_LINE" | grep -q "BEGIN PKCS7"; then
  if grep -q "BEGIN CERTIFICATE" "$CA_CERT"; then
    warn "CA cert has extra content before the certificate data"
    echo "       Akeyless may fail to parse this. Strip everything outside the BEGIN/END markers:"
    echo "       sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' ${CA_CERT} > ca-clean.pem"
  fi
fi

echo ""

# ---------------------------------------------------------------------------
# 2. CA chain - individual certificate validation
# ---------------------------------------------------------------------------
echo "[2] CA Chain - Individual Certificate Validation"

CERT_COUNT=$(grep -c "BEGIN CERTIFICATE" "$CA_CERT" 2>/dev/null || echo "0")
echo "  Certificates in chain file: ${CERT_COUNT}"

if [ "$CERT_COUNT" -eq 0 ]; then
  fail "No certificates found in ${CA_CERT}"
else
  # Split the chain into individual certs and validate each one
  TMPDIR=$(mktemp -d)
  csplit -f "${TMPDIR}/cert-" -z -s "$CA_CERT" '/-----BEGIN CERTIFICATE-----/' '{*}' 2>/dev/null || true

  CERT_INDEX=0
  for f in "${TMPDIR}"/cert-*; do
    # Skip empty files (csplit sometimes creates an empty first file)
    if [ ! -s "$f" ] || ! grep -q "BEGIN CERTIFICATE" "$f" 2>/dev/null; then
      continue
    fi
    CERT_INDEX=$((CERT_INDEX + 1))
    SUBJ=$(openssl x509 -in "$f" -noout -subject 2>/dev/null || echo "DECODE FAILED")
    ISSUER=$(openssl x509 -in "$f" -noout -issuer 2>/dev/null || echo "DECODE FAILED")

    if echo "$SUBJ" | grep -q "DECODE FAILED"; then
      fail "Certificate #${CERT_INDEX} in chain FAILED TO DECODE"
      echo "       This causes the 'failed to decode intermediate certificate' error in Akeyless."
      echo ""
      echo "       Problem:  The base64 data in certificate #${CERT_INDEX} cannot be parsed as an X.509 certificate."
      echo "       Causes:   - Corrupted or truncated base64 encoding"
      echo "                 - Extra text or whitespace inside the BEGIN/END markers"
      echo "                 - PKCS7 content wrapped in PEM certificate markers"
      echo "                 - File was modified or copy-pasted incorrectly"
      echo ""
      echo "       Fix:      Re-export certificate #${CERT_INDEX} from your CA and rebuild the chain."
      echo "                 If you have the original cert file, re-encode it cleanly:"
      echo "                   openssl x509 -in original-cert.pem -out clean-cert.pem"
      echo "                 Then rebuild:  cat intermediate-ca.pem root-ca.pem > ca-chain.pem"
    else
      IS_CA=$(openssl x509 -in "$f" -noout -text 2>/dev/null | grep -c "CA:TRUE" || true)
      if [ "$IS_CA" -gt 0 ]; then
        pass "Certificate #${CERT_INDEX} (CA): ${SUBJ}"
      else
        pass "Certificate #${CERT_INDEX} (leaf): ${SUBJ}"
      fi
    fi
  done

  # Check for missing newline between concatenated certs
  if grep -q "END CERTIFICATE.*BEGIN CERTIFICATE" "$CA_CERT" 2>/dev/null; then
    fail "Missing newline between certificates in chain file"
    echo "       The END and BEGIN markers are on the same line. Fix with:"
    echo "       awk '/-----END CERTIFICATE-----/{print; print \"\"; next}1' ${CA_CERT} > fixed.pem && mv fixed.pem ${CA_CERT}"
  fi

  rm -rf "${TMPDIR}"
fi

if [ "$CERT_COUNT" -eq 1 ]; then
  echo ""
  warn "Chain file contains only 1 certificate"
  echo "       If your client cert was signed by an intermediate CA, you need both"
  echo "       the intermediate and root CA certificates in the chain file:"
  echo "         cat intermediate-ca.pem root-ca.pem > ca-chain.pem"
fi

echo ""

# ---------------------------------------------------------------------------
# 3. CA Certificate details
# ---------------------------------------------------------------------------
echo "[3] CA Certificate Details"
if openssl x509 -in "$CA_CERT" -noout -subject -issuer -dates 2>/dev/null; then
  pass "CA certificate is readable"
else
  fail "Cannot read CA certificate"
fi
echo ""

# ---------------------------------------------------------------------------
# 4. Client Certificate details
# ---------------------------------------------------------------------------
echo "[4] Client Certificate Details"
if openssl x509 -in "$CLIENT_CERT" -noout -subject -issuer -dates 2>/dev/null; then
  pass "Client certificate is readable"
else
  fail "Cannot read client certificate"
fi
echo ""

# ---------------------------------------------------------------------------
# 5. Chain verification
# ---------------------------------------------------------------------------
echo "[5] Chain Verification"
VERIFY_OUTPUT=$(openssl verify -CAfile "$CA_CERT" "$CLIENT_CERT" 2>&1 || true)
if echo "$VERIFY_OUTPUT" | grep -q ": OK"; then
  pass "Client cert is signed by the CA chain"
else
  fail "Chain verification failed"
  echo "  OpenSSL output: $VERIFY_OUTPUT"
  echo ""
  if echo "$VERIFY_OUTPUT" | grep -q "unable to get local issuer"; then
    echo "  Problem:  The client certificate was signed by a CA that is not in your chain file."
    echo "            This usually means the chain is missing the intermediate CA certificate."
    echo "  Fix:      Get the intermediate CA cert from your PKI team and rebuild the chain:"
    echo "              cat intermediate-ca.pem root-ca.pem > ca-chain.pem"
  elif echo "$VERIFY_OUTPUT" | grep -q "certificate has expired"; then
    echo "  Problem:  A certificate in the chain or the client cert has expired."
    echo "  Fix:      Check the expiration dates below (section 8) and reissue the expired cert."
  elif echo "$VERIFY_OUTPUT" | grep -q "Error loading"; then
    echo "  Problem:  The CA chain file could not be loaded. It may be corrupted or in the wrong format."
    echo "  Fix:      Check sections 1 and 2 above for format and encoding errors."
  else
    echo "  Problem:  The client certificate's signature does not trace back to the CA chain you provided."
    echo "  Fix:      Verify you exported the correct CA certificates from the PKI that issued the client cert."
    echo "            Check the issuer field: openssl x509 -in ${CLIENT_CERT} -noout -issuer"
  fi
fi
echo ""

# ---------------------------------------------------------------------------
# 6. Extended Key Usage
# ---------------------------------------------------------------------------
echo "[6] Extended Key Usage (clientAuth)"
# Try -ext first (OpenSSL 1.1.1+), fall back to -text parsing (all versions)
EKU=$(openssl x509 -in "$CLIENT_CERT" -noout -ext extendedKeyUsage 2>/dev/null || \
      openssl x509 -in "$CLIENT_CERT" -noout -text 2>/dev/null | grep -A1 "Extended Key Usage" || true)
if echo "$EKU" | grep -qi "Client Authentication\|clientAuth"; then
  pass "clientAuth EKU present"
else
  fail "clientAuth EKU missing - Akeyless will reject this certificate"
  echo "  Current EKU: ${EKU:-none}"
  echo ""
  echo "  Problem:  The client certificate does not include the 'TLS Web Client Authentication'"
  echo "            extended key usage. Akeyless requires this to accept the cert for authentication."
  echo "  Fix:      Reissue the certificate from your CA using a client authentication template."
  echo "            For openssl: add '-extfile <(echo extendedKeyUsage=clientAuth)' when signing."
  echo "            For enterprise CAs: request a cert with the 'Client Authentication' EKU enabled."
fi
echo ""

# ---------------------------------------------------------------------------
# 7. Private Key match
# ---------------------------------------------------------------------------
echo "[7] Private Key Match"
CERT_PUB=$(openssl x509 -in "$CLIENT_CERT" -noout -pubkey 2>/dev/null | openssl dgst -md5)
KEY_PUB=$(openssl pkey -in "$CLIENT_KEY" -pubout 2>/dev/null | openssl dgst -md5)
if [ -z "$KEY_PUB" ]; then
  fail "Cannot read private key"
  echo "  Problem:  The private key file could not be parsed. It may be passphrase-protected,"
  echo "            in DER format, or in PKCS8/PKCS12 format instead of PEM."
  echo "  Fix:      - Passphrase-protected: openssl pkey -in ${CLIENT_KEY} -out key-decrypted.pem"
  echo "            - DER format: openssl pkey -in ${CLIENT_KEY} -inform DER -out key.pem"
  echo "            - PKCS12: openssl pkcs12 -in bundle.pfx -out key.pem -nocerts -nodes"
elif [ "$CERT_PUB" = "$KEY_PUB" ]; then
  pass "Private key matches certificate"
else
  fail "Private key does NOT match certificate"
  echo ""
  echo "  Problem:  The private key in ${CLIENT_KEY} was not used to generate the certificate in ${CLIENT_CERT}."
  echo "            These two files must be a matching pair from the same CSR/key generation."
  echo "  Fix:      Verify which key was used to generate the cert:"
  echo "              openssl x509 -in ${CLIENT_CERT} -noout -pubkey | openssl dgst -sha256"
  echo "              openssl pkey -in ${CLIENT_KEY} -pubout | openssl dgst -sha256"
  echo "            The SHA-256 hashes must match. If they don't, locate the correct private key"
  echo "            or regenerate a new key+CSR and have your CA sign it again."
fi
echo ""

# ---------------------------------------------------------------------------
# 8. Expiration check
# ---------------------------------------------------------------------------
echo "[8] Expiration"
if openssl x509 -in "$CLIENT_CERT" -noout -checkend 0 2>/dev/null; then
  pass "Client certificate is not expired"
  EXPIRY_DATE=$(openssl x509 -in "$CLIENT_CERT" -noout -enddate 2>/dev/null | cut -d= -f2)
  echo "       Expires: ${EXPIRY_DATE}"
  if ! openssl x509 -in "$CLIENT_CERT" -noout -checkend 2592000 2>/dev/null; then
    warn "Client certificate expires within 30 days - plan for renewal"
  fi
else
  EXPIRY_DATE=$(openssl x509 -in "$CLIENT_CERT" -noout -enddate 2>/dev/null | cut -d= -f2)
  fail "Client certificate is expired (was valid until: ${EXPIRY_DATE})"
  echo "  Problem:  Akeyless will reject expired certificates during authentication."
  echo "  Fix:      Reissue the client certificate from your CA:"
  echo "            1. Generate a new CSR:  openssl req -new -key ${CLIENT_KEY} -out new.csr -subj \"/CN=your-cn\""
  echo "            2. Submit to your CA for signing with clientAuth EKU"
  echo "            3. Replace ${CLIENT_CERT} with the new certificate"
fi

if openssl x509 -in "$CA_CERT" -noout -checkend 0 2>/dev/null; then
  pass "CA certificate is not expired"
  CA_EXPIRY=$(openssl x509 -in "$CA_CERT" -noout -enddate 2>/dev/null | cut -d= -f2)
  echo "       Expires: ${CA_EXPIRY}"
else
  CA_EXPIRY=$(openssl x509 -in "$CA_CERT" -noout -enddate 2>/dev/null | cut -d= -f2)
  fail "CA certificate is expired (was valid until: ${CA_EXPIRY})"
  echo "  Problem:  An expired CA certificate means Akeyless cannot validate any client certs signed by it."
  echo "  Fix:      Get the renewed CA certificate from your PKI team and update the auth method:"
  echo "              akeyless auth-method update cert --name \"/Auth/CertificateAuth\" \\"
  echo "                --certificate-data \"\$(base64 -w0 new-ca-chain.pem)\""
fi
echo ""

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "=============================================="
echo "  RESULTS"
echo "=============================================="
echo "  Passed:   ${PASS}"
echo "  Warnings: ${WARN}"
echo "  Failed:   ${FAIL}"
echo "=============================================="

if [ "$FAIL" -eq 0 ]; then
  echo ""
  echo "  All checks passed. Safe to create the Akeyless cert auth method."
  echo ""
  echo "  Next step:"
  echo "    akeyless auth-method create cert \\"
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
