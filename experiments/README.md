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
1. Builds the core crate and runs every unit test whose path contains service_grant. That is everything in the service_grant module, including the provider tests in service.rs. It may also pick up other tests with that string in their name, such as lifecycle hooks. It then runs the crate's doc-tests, with the same filter.
```
cargo test -p openstack-keystone-core service_grant
```

2. Runs the same crate but filters to tests whose name contains test_create_. It is a faster, narrower loop on the create path. It runs the test_create_* tests from the first command. The filter is not scoped to service grants, so it will also run any unrelated test_create_* test in the crate, such as user or project tests. Note that test_deadline_after doesn't match test_create_, so run it through the first command or by name. The expected result is that all tests pass. Extra unrelated tests in the count are normal.
```
cargo test -p openstack-keystone-core test_create_
```

3. This builds the core-types crate and runs the tests matching service_grant, which here are the tests in service_grant/resource.rs. test_redeemable checks that is_redeemable is false for an expired or disabled grant and true for a future expiry. A grant with expires_at: None is still redeemable, which is why existing no-expiry grants keep working. test_with_update checks that lifecycle updates bump the version and set or clear disabled_reason.
```
cargo test -p openstack-keystone-core-types service_grant
```

4. This builds the API-types crate with every feature enabled, then runs all of its tests and doc-tests with no filter. The --all-features flag turns on validate (the validator derives) and openapi (the utoipa::ToSchema and IntoParams derives). It tests no new behaviour. The change here is doc comments on ServiceGrant.expires_at and ServiceGrantCreate.expires_at, and the command confirms the crate still compiles with the derives that turn those comments into OpenAPI schema descriptions. Any serialization tests in the crate also run.
```
cargo test -p openstack-keystone-api-types --all-features`
```

### Token Expiry Rules
```
cargo test -p openstack-keystone-core oauth2_client::token_exchange::tests
```
```
cargo test -p openstack-keystone api::v4::oauth2::token::token_exchange::tests
```

### Token Exchange Validation
Run from the root of the `demo-3` fork clone. The checkout must include PR #1575.

```bash
cargo test -p openstack-keystone --lib token_exchange
```

This runs the token exchange handler tests. It checks that existing
`access_token` requests still work, that missing, empty, or unsupported
subject token types are rejected, and that successful responses include
`issued_token_type`.

**Expected runtime:** Several minutes on a clean build; later runs reuse the build.
**Expected output:** All matching tests pass with `0 failed`. The exact count
depends on the branch revision.


### External JWT Exchange

Run these commands from the root of the `millionsouls/keystone`
fork checkout on branch `demo-3`, not from the documentation repository.

#### 1. External assertion handler

```bash
cargo test -p openstack-keystone external_assertion::tests
```

Exercises the external JWT exchange handler using mocked providers and
local HTTP fixtures. Coverage includes:

- Trusted-issuer selection and OIDC discovery/JWKS retrieval.
- Successful signature verification, identity mapping, and token issuance.
- Issued identity, roles, audience, mapping version, and expiry claims.
- Rejection of untrusted issuers, invalid signatures, incorrect audiences,
  expired assertions, and replayed assertions.
- Failure before mapping when replay protection is unavailable.
- Mapping failures that do not consume replay-cache capacity.
- HTTP 503 responses when replay-cache capacity is exhausted.

**Verified result:** `8 passed; 0 failed` on commit `7aab548f`.

#### 2. Issued-token lifetime

```bash
cargo test -p openstack-keystone-core external_token_expiry_never_exceeds_assertion_expiry
```

Checks that the issued token expires no later than either the configured
access-token expiry or the external assertion's expiry. It also checks
rejection when no positive lifetime remains.

**Verified result:** `1 passed; 0 failed` on commit `7aab548f`.

#### 3. Replay configuration validation

```bash
cargo test -p openstack-keystone-config assertion_replay
```

Checks valid default limits and rejects invalid replay-cache bounds,
including zero capacity and nested limits exceeding their totals.

**Verified result:** `1 passed; 0 failed` on commit `7aab548f`.

**Expected runtime:** Initial compilation may take several minutes.
With dependencies already built, the verification run took approximately
52 seconds, 24 seconds, and less than one second respectively, including
incremental compilation. Runtime varies by machine and build cache.

**Expected output:** Each command reports the matching tests as passed
with `0 failed`. Additional test targets may report zero matching tests.
Counts may change on later branch revisions.

**Dependencies and limitations:** These tests require the Rust and system
build dependencies described in the design document. They create their
own test state and do not require a running Keystone server, Keycloak,
or changes to `keystone.conf`.

This experiment demonstrates unit/component behavior, not a live
Keycloak-to-Keystone exchange. The success test inspects the issued
token's claims but does not independently verify its signature.

## Conform with contributor and security expectations
1. ```cargo clippy -p openstack-keystone-core --all-targets``` Catch common mistakes, optimize code, and enforce style guidelines
2. ```cargo check -p openstack-keystone --message-format=short``` Verifies everything complies together
