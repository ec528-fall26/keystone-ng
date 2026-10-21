# Experiments
One script per claim. Each script should be runnable from the repository root,
print what it is measuring, and finish in a bounded amount of time.

Every script here must have a matching entry in
[`../docs/design-document.md`](../docs/design-document.md) stating what it
supports, how long it takes, and what output to expect.

### Where to run these
The code is in our fork, not this repo. Clone the `demo-2` branch and run all the commands below inside that folder:
```
git clone -b demo-2 https://github.com/millionsouls/keystone.git
cd keystone
git branch --show-current
```
The last command should print `demo-2`. You need Rust and `protoc` (see Setup in the design document).

## Token Lifetime Expiry Cap
1. ```cargo test -p openstack-keystone-core oauth2_client::token_exchange::tests``` Verifies expiry rules are in place
2. ```cargo test -p openstack-keystone api::v4::oauth2::token::token_exchange::tests``` Pings token endpoints

## JWT Verification Demo
1. Checks 8 tokens against a fake identity provider. Only the valid one is ACCEPTED. The other 7 are REJECTED: untrusted issuer, issuer of a disabled provider, wrong audience, empty audience list, expired, HS256, and a token changed after signing. It ends with `1 passed; 0 failed`.
```
cargo test -p openstack-keystone --lib demo_external_jwt_verification -- --nocapture
```
2. All the JWT verification tests (bad signature, wrong key, `alg: none`, untrusted issuer and so on). It ends with `65 passed; 0 failed`.
```
cargo test -p openstack-keystone --lib federation::api::oidc_utils
```
3. The token exchange tests, which include the external JWT cases (trusted issuer accepted, untrusted issuer rejected, token made for a different client rejected). It ends with `17 passed; 0 failed`.
```
cargo test -p openstack-keystone --lib api::v4::oauth2::token::token_exchange::tests
```

## Token-exchange request validation
Verify the external JWT demonstration separately
```
cargo test -p openstack-keystone --lib api::v4::oauth2::token::token_exchange::tests -j 1
```

## Validation Profile for OAuth2 subject tokens
Navigate your Terminal to the crates/core folder to run the cargo tests
```
cd crates/core
cargo test -p openstack-keystone-core verify::tests
```

## Conform with contributor and security expectations
```
cd crates/core
```
1. ```cargo clippy -p openstack-keystone-core --all-targets``` Catch common mistakes, optimize code, and enforce style guidelines
2. ```cargo check -p openstack-keystone --message-format=short``` Verifies everything complies together
3. ```cargo fmt --check``` Ensures proper code format as part of Keystone contributer documents

