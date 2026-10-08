# Issue #5: Token exchange subject token type

Implementation for [issue #5](https://github.com/ec528-fall26/keystone-ng/issues/5).
This directory contains a patch against the existing Keystone service, not
an independently buildable Rust crate. No upstream source snapshot is included.

## Base version

Repository: https://github.com/openstack-experimental/keystone

Commit: `97a71e278eb0253d182f0868ad2990b244afd5a3`

## Changes

The upstream dispatcher already handles the RFC 8693 token-exchange grant.
The patch changes only:

- `crates/keystone/src/api/v4/oauth2/token.rs`: document the JWT subject type
  and remove the unused-field annotation.
- `crates/keystone/src/api/v4/oauth2/token/token_exchange.rs`: require
  `urn:ietf:params:oauth:token-type:jwt`; return HTTP 400 and OAuth
  `invalid_request` for missing or unsupported types; update four existing
  tests and add two error-path tests.

This preserves upstream client authentication and delegated token validation.
It does not implement external issuer discovery or external JWT verification.

## Apply and test

Run from the root of this course repository. The destination directory must
not already exist. Requires Git, Rust >= 1.94, and upstream build prerequisites.

```sh
git clone https://github.com/openstack-experimental/keystone.git /tmp/keystone-issue-5
git -C /tmp/keystone-issue-5 checkout --detach 97a71e278eb0253d182f0868ad2990b244afd5a3
git -C /tmp/keystone-issue-5 apply --check "$PWD/src/keystone-token-exchange/subject-token-type.patch"
git -C /tmp/keystone-issue-5 apply "$PWD/src/keystone-token-exchange/subject-token-type.patch"
cd /tmp/keystone-issue-5
cargo test -p openstack-keystone test_token_exchange -j 1
```

## Validation

The author ran the command above against the same patched source locally:
**7 passed, 0 failed, 1257 filtered out** (2026-10-08).

Coverage includes successful application-credential exchange, rejected trust
and non-delegated subjects, unauthorized client, missing subject token, and
missing/unsupported subject token types. The full test suite was not run.

The patch was also checked for clean application against the pinned upstream
commit, and the resulting two files were compared with the tested implementation
in commit `c28de9e` on `Zebang`.
