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

### Token Lifetime Expiry Cap
1. ```cargo test -p openstack-keystone-core oauth2_client::token_exchange::tests``` Verifies expiry rules are in place
2. ```cargo test -p openstack-keystone api::v4::oauth2::token::token_exchange::tests``` Pings token endpoints
3. ```cargo check -p openstack-keystone --message-format=short``` Verifies everything complies together
4. ```cargo fmt --check``` Ensures proper code format as part of Keystone contributer documents

### JWT Verification Demo
```
./experiments/external-jwt-demo.sh
```

Run this inside the fork folder from above. The first build takes a few minutes, after that it is quick.

The script runs two things:
1. `demo_external_jwt_verification` sets up a fake identity provider and checks 8 tokens. Only the valid one is ACCEPTED. The other 7 are REJECTED: untrusted issuer, issuer of a disabled provider, wrong audience, empty audience list, expired, HS256, and a token changed after signing.
2. The token exchange tests, which include the external JWT cases (trusted issuer accepted, untrusted issuer rejected, token made for a different client rejected).

If it all passes, the last line is `OK: demo passed and all 17 token exchange tests passed.`

To also run all the JWT verification tests (65):
```
cargo test -p openstack-keystone --lib federation::api::oidc_utils
```

### Token-exchange request validation
Verify the external JWT demonstration separately
```
cargo test -p openstack-keystone --lib api::v4::oauth2::token::token_exchange::tests -j 1
```

