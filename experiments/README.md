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

## External JWT Verification
### JWT Verification Demo
```
experiments/external-jwt-demo.sh
```
