# Issue #5: Token exchange subject token type

Issue: https://github.com/ec528-fall26/keystone-ng/issues/5

## Source

`src/keystone` contains the complete upstream source (Apache-2.0), from
https://github.com/openstack-experimental/keystone at commit
`97a71e278eb0253d182f0868ad2990b244afd5a3`.
The source import and issue fix are separate commits for review.

## Behavior

The upstream `/token` dispatcher already routes
`urn:ietf:params:oauth:grant-type:token-exchange` to its dedicated handler.
This change requires `subject_token_type` to equal
`urn:ietf:params:oauth:token-type:jwt` before client authentication and
subject-token validation. Missing or unsupported types return HTTP 400
with an OAuth `invalid_request` error and a specific description.

The four existing success/authorization/delegation tests now supply the JWT
type. Two new router tests cover missing and unsupported types.
This is a request-type gate; it retains upstream token validation and does
not implement external issuer discovery or a new JWT verification backend.

## Validation

From `src/keystone`, with Rust >= 1.94 and upstream build prerequisites:

```sh
cargo test -p openstack-keystone test_token_exchange
cargo fmt -p openstack-keystone -- --check
pre-commit run --all-files
```

`git diff --check` passed. Tests and pre-commit could not run in the editing
environment because `cargo` and `pre-commit` are not installed. Runtime
behavior has therefore not been verified locally.
