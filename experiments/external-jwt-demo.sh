#!/bin/sh
# Runs the external JWT demo (issue #6).
# Downloads Keystone, applies the three patches from src/external-jwt/, runs the tests.
# Usage: experiments/external-jwt-demo.sh [folder]   (default /tmp/keystone-issue-6)
set -e

REPO=$(cd "$(dirname "$0")/.." && pwd)
PATCHES="$REPO/src/external-jwt"
BASE=462a4123b98d6b731dc11193c46eb5977a94da3c
DIR=${1:-/tmp/keystone-issue-6}

if [ -e "$DIR" ]; then
    echo "$DIR already exists, delete it or pass another folder" >&2
    exit 1
fi

git clone -q https://github.com/openstack-experimental/keystone.git "$DIR"
git -C "$DIR" checkout -q --detach "$BASE"
git -C "$DIR" apply "$PATCHES/1-verification.patch"
git -C "$DIR" apply "$PATCHES/2-bound-issuer.patch"
git -C "$DIR" apply "$PATCHES/3-demo-test.patch"

echo "Measuring: verify_external_jwt accepts a token from a trusted issuer and rejects 7 bad ones"
echo "The first build takes several minutes"
cd "$DIR"
cargo test -p openstack-keystone --lib demo_external_jwt_verification -- --nocapture
cargo test -p openstack-keystone --lib federation::api::oidc_utils
