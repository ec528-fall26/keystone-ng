# Experiments
One script per claim. Each script should be runnable from the repository root,
print what it is measuring, and finish in a bounded amount of time.

Every script here must have a matching entry in
[`../docs/design-document.md`](../docs/design-document.md) stating what it
supports, how long it takes, and what output to expect.

### Where to run these
The code is in our fork, not this repo. Clone the `demo-3` branch and run all the commands below inside that folder:
```
git clone -b demo-3 https://github.com/millionsouls/keystone.git
cd keystone
git branch --show-current
```
The last command should print `demo-3`. You need Rust and `protoc` (see Setup in the design document).

### Service Grant Chain
1. Runs the configuration crate’s unit and documentation tests. It verifies that Keystone’s configuration types, including the [oauth2] access_token_lifetime_minutes setting, continue to deserialize and validate correctly. It also checks that the setting the service-grant logic now reads remains available through the configuration layer.
```
cargo test -p openstack-keystone-config
```

2. Runs the core crate’s service-grant creation tests matching test_create_. These tests check that a grant uses the configured OAuth2 access-token lifetime only when no explicit expiry or client maximum is present; that a client maximum and a valid explicit expiry retain their precedence; and that an out-of-range client maximum returns an error instead of causing a panic.
```
cargo test -p openstack-keystone-core service_grant::service::tests::test_create_
```

## Conform with contributor and security expectations
1. ```cargo clippy -p openstack-keystone-core --all-targets``` Catch common mistakes, optimize code, and enforce style guidelines
2. ```cargo check -p openstack-keystone --message-format=short``` Verifies everything complies together

