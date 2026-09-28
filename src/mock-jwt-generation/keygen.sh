#!/usr/bin/env bash
# keygen.sh
#
# Generates two RSA-2048 key pairs as committed test fixtures:
#   test-private.pem / test-public.pem   - sign and verify valid tokens
#   rogue-private.pem / rogue-public.pem - produce invalid-signature vectors
#

set -euo pipefail

KEYS_DIR="keys"
mkdir -p "$KEYS_DIR"

generate_pair() {
    local name="$1"
    local priv="$KEYS_DIR/$name-private.pem"
    local pub="$KEYS_DIR/$name-public.pem"

    if [[ -f "$priv" && -f "$pub" ]]; then
        echo "    $name keys already exist - skipping (delete to regenerate)"
        return
    fi

    echo "  Generating $name key pair (RSA 2048-bit)..."

    # PKCS#8 private key - accepted by jsonwebtoken::EncodingKey::from_rsa_pem
    openssl genpkey \
        -algorithm RSA \
        -pkeyopt rsa_keygen_bits:2048 \
        -out "$priv" \
        2>/dev/null

    # SubjectPublicKeyInfo public key - accepted by DecodingKey::from_rsa_pem
    openssl pkey \
        -pubout \
        -in  "$priv" \
        -out "$pub"

    echo "Private: $priv"
    echo "Public: $pub"
}

echo "\nGenerating RSA key pairs for test fixtures..."
generate_pair "test"
generate_pair "rogue"
echo "\nTest keys in $KEYS_DIR/"
