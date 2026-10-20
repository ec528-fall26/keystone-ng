# Experiments

One script per claim. Each script should be runnable from the repository root,
print what it is measuring, and finish in a bounded amount of time.

Every script here must have a matching entry in
[`../docs/design-document.md`](../docs/design-document.md) stating what it
supports, how long it takes, and what output to expect.


### Token Lifetime Expiry Cap
1. ```cargo test -p openstack-keystone-core oauth2_client::token_exchange::tests``` Verifies expiry rules are in place
2. ```cargo test -p openstack-keystone api::v4::oauth2::token::token_exchange::tests``` Pings token endpoints
3. ```cargo check -p openstack-keystone --message-format=short``` Verifies everything complies together
4. ```cargo fmt --check``` Ensures proper code format as part of Keystone contributer documents

### JWT Verification Demo
```
experiments/external-jwt-demo.sh
```

Run it from the repo root on the `demo-2` branch. You need Rust and `protoc`, and the first build takes a few minutes.

It runs two things:
1. `demo_external_jwt_verification` starts a mock identity provider and checks 8 tokens against it. Only the valid one should be ACCEPTED. The other 7 should be REJECTED: untrusted issuer, issuer of a disabled provider, wrong audience, empty audience list, expired, HS256, and a changed payload.
2. The token exchange tests, which include the external JWT cases: a JWT from a trusted issuer is accepted, one from an untrusted issuer is rejected, and one made for a different client is rejected.

If everything passes, the last line is `OK: demo passed and all 17 token exchange tests passed.`

### Token-exchange request validation
Verify the external JWT demonstration separately
```
cargo test -p openstack-keystone --lib api::v4::oauth2::token::token_exchange::tests -j 1
```

