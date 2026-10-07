# keystone-jwt-verify

Verifies an external JWT (the `subject_token` of an RFC 8693 token exchange)
against the JWKS of a trusted issuer, found through OIDC discovery.
EC528 Keystone-NG, issue #6.

```
verify_external_jwt(token, trusted_issuers, audiences, client)
  1. extract_issuer     read `iss` from the unverified payload
  2. allowlist check    `iss` must be in `trusted_issuers` (before any network call)
  3. oidc::discover     {issuer}/.well-known/openid-configuration
  4. oidc::fetch_jwks   the `jwks_uri` from the discovery document
  5. verify_jwt         signature, iss, exp/nbf/iat, aud
```

Only asymmetric algorithms are accepted. Redirects are disabled in
`oidc::build_http_client`.

`discover`, `fetch_jwks` and `verify_jwt` follow the helpers in
openstack-experimental/keystone (`crates/keystone/src/federation/api/oidc_utils.rs`,
Apache-2.0), so the new code can be moved there later.

## Run

```
cargo test
cargo clippy --all-targets
cargo fmt
```

Needs Rust 1.94 or newer. Test keys in `src/test_util.rs` are throwaway.
