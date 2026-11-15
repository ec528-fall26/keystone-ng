# Design Document

*Due in the `demo-3` branch, updated for `demo-3` and `final-demo`.
**The TA will run this document.** If they cannot follow it, you lose the points.*

## 1. Architecture

1. [Issue](https://github.com/openstack-experimental/keystone/issues/1636) :: [PR](https://github.com/openstack-experimental/keystone/pull/1639) :: Each token validation profile now has a list of allowed signing algorithms. External tokens accept RS256 and ES256 by default. HMAC and `alg: none` tokens are rejected. Merged. Code diff under: `src/demo-3/allowed-algorithms/1639.patch`
2. [Issue](https://github.com/openstack-experimental/keystone/issues/1636) :: [PR](https://github.com/openstack-experimental/keystone/pull/1642) :: Follow-up to #1639 for the maintainer's review: an allowlist instead of a banned list, a separate error for a bad list, and wrong-key-type tests. Code diff under: `src/demo-3/allowed-algorithms/1642.patch`
3. [Issue](https://github.com/openstack-experimental/keystone/issues/1636) :: [PR](https://github.com/openstack-experimental/keystone/pull/1640) :: A replay cache that remembers the `jti` of external tokens so the same token can't be used twice. Code diff under: `src/demo-3/replay-cache/1640.patch`
4. [Issue](https://github.com/openstack-experimental/keystone/issues/1353) || [PR](https://github.com/openstack-experimental/keystone/pull/1616) :: Follow-up to previous token expiration PR, this applies a default token expiration on a token that does not come with a expiration instead of silently dropped or erroring.
5. [No Direct Issue](https://github.com/openstack-experimental/keystone/issues/1353) || [PR]() 
:: From the project mentor, checks service grant chain and applies a default expiration on any service grants. This is based on a chain of if: grant has a specific expiration, client has a set max_grant_lifetime, then default_access_lifetime.
6. [Issue #1354](https://github.com/openstack-experimental/keystone/issues/1354) :: [PR](https://github.com/openstack-experimental/keystone/pull/1575) :: Added RFC 8693 request validation to Keystone’s token exchange endpoint. Missing, empty, or unsupported subject token types return `invalid_request`, and successful responses include `issued_token_type`. Merged.  Code diff under: src/demo-3/1575.patch
7. [Issue #1366](https://github.com/openstack-experimental/keystone/issues/1366) :: [PR](https://github.com/openstack-experimental/keystone/pull/1646) :: Added a test fixture for user and service account JWTs from Keycloak. The full token exchange test in k3s is still in progress.

## 2. Design decisions
### 1. PR 1639/1642/1640
**Background.** A JWT has a header, claims and a signature. The signature shows the identity provider made the token and nobody changed it, and the `alg` header says how it was signed.
- **RS256** is an RSA signature with SHA-256. The provider signs with a private key and Keystone checks with the public key.
- **ES256** is the same idea with an elliptic curve (ECDSA, P-256), so the keys and signatures are smaller.
- **HS256** uses one shared secret to sign and check. Keystone only has the provider's public key, so an attacker could use that public key as the secret and forge a token that passes. That is why HMAC is rejected.
1. The single `expected_algorithm` argument of `verify_subject_token_jwt` is removed, and each profile has a list of allowed algorithms. Keystone-native profiles allow only the configured signing algorithm. External profiles allow RS256 and ES256, and `with_allowed_algorithms` can change that. The `alg` in the header is checked against the list before any key is looked up. HMAC, `alg: none` and an empty list are rejected.
2. The maintainer asked for three changes in review, done in #1642. The HMAC check was a list of banned algorithms, so a new HMAC algorithm would get through. It is now a list of allowed ones (RS256/384/512, PS256/384/512, ES256/384, EdDSA). A bad list used `InvalidProfile`, whose message is about issuers and audiences, so it now has its own error, `InvalidAlgorithmList`. Tests were also added for a key of the wrong type (ES256 token with an RSA-only JWKS, RS256 token with an EC-only JWKS). The crypto library already rejects these, so no code changed. `crypto-inventory.md` is updated too.
3. An external token is valid for a few minutes, so a copied one could be used again. The replay cache stores each accepted `jti` per domain and issuer until `exp` plus the 60 second clock skew, and refuses it a second time. When full it refuses new tokens and never deletes live entries, otherwise an attacker could flood it to push out a copied token's entry and replay it. The DPoP cache logic moved into a general `ReplayCache` that `DpopReplayCache` and the new `AssertionReplayCache` both use. The 9 existing DPoP tests are unchanged.

### 3. PR 1616
While permanent tokens (those without an expiry) are possibles are not technically against RFC guidelines, they can present significant securrity risks if not handled properly. We force all tokens to have an expiry and if one come that does not have one, we apply a default limit of 15 minutes. This applies to both subject tokens and application credentials.

Focusing on applications then, we move onto a service grant chain which is a type of delegation chain, two of which exist in Keystone. We focus on service grant, which is like 'giving permission in advance'.

`User → create service-grant record → service redeems it → delegated access token`
An authenticated user creates a grant naming a service client, project, and role set. The roles must be within the user’s effective roles and the client’s delegation ceiling (grant creation).

The service (etc Cinder) redeems it with the custom `urn:openstack:params:oauth:grant-type:service-grant` grant type. Redemption requires a matching SVID on the internal interface; Keystone rechecks the grant, grantor, and live roles (handler, core redemption). The token represents the user as sub, the service as act, and carries the grant/project in delegation_context (claim construction).

Essentially, a user tells Keystone "Let this service act for me on this project, with these roles". The service then proves its identity via a SPIFFE certificate and asks Keystone for a short-lived access token. Keystone checks that the grant is still valid and that the user still has the relevant roles. The token says who the user is (sub) and which service is acting (act). The service can request another token later by redeeming the grant again. Revoking the grant prevents future redemptions, though already-issued tokens remain usable until they expire.

Permanent or overly long-lived service grants are dangerous because they violate the Principle of Least Privilege. Service tokens travel extensively across internal control plane networks to facilitate inter-service communication (e.g., Nova talking to Cinder or Neutron). If an internal control plane node is compromised, or if a service token accidentally leaks into debug logs or unencrypted databases, a permanent grant gives an attacker an indefinite, unexpiring key to cloud infrastructure.


## 3. Setup
_Exact dependencies, versions, and hardware assumptions. Written so that someone
starting from a clean machine can follow it._

Rust will need to be installed on the machine. If using VSCode, instructions are on the official website [here](https://code.visualstudio.com/docs/languages/rust).

1. Install the Rust tool chain [here](https://rustup.rs). This installer is for Windows, MacOS and Linux. 
2. Rust-Anlyzer is also avaliable on the VSCode extensions
3. Check if rust is installed (This workspace requires Rust 1.96 or later):
```
rustc --version
cargo --version
rustup show
```
4. The formatting and lint components can be installed or refreshed with:
```
rustup component add rustfmt clippy
```
5. Clone to Openstack Keystone fork repo: (This is our testing fork). Our code is on the `demo-3` branch, so clone that branch:
```
git clone -b demo-3 https://github.com/millionsouls/keystone.git
cd keystone
git branch --show-current
```
6. The last command should print `demo-3`.
7. Keystone needs `protoc` to build. MacOS: ```brew install protobuf```. Ubuntu: ```sudo apt-get install protobuf-compiler pkg-config 
libssl-dev```.

## 4. Running the experiments
Run every command inside the fork clone from Setup (`millionsouls/keystone`, branch `demo-3`), not in this repo.

### [1] Allowed signing algorithms
| Item | Details |
| --- | --- |
| Supports | Algorithms not on the list, HMAC, `alg: none` and wrong key types are rejected (PRs #1639 and #1642). |
| Command | `cargo test -p openstack-keystone-core --lib -- oauth2_client::verify::tests::external_profile oauth2_client::verify::tests::profile_allows_only` |
| Expected runtime | 5 to 10 minutes the first time (compiling), about 10 seconds after. |
| Expected output | `9 passed; 0 failed` |

### [2] Replay cache
| Item | Details |
| --- | --- |
| Supports | The same `jti` is refused the second time, a full cache keeps live entries, and the DPoP cache works as before (PR #1640). |
| Command | `cargo test -p openstack-keystone-core --lib replay` |
| Expected runtime | A few seconds, the build is already done by experiment [1]. |
| Expected output | `23 passed; 0 failed` (8 general cache, 6 assertion cache, 9 DPoP cache) |

## [3] Token Default Expiry
| Item | Details |
| --- | --- |
| Supports | Presented token with no expiry should have a default of 15 minutes applied. |
| Command | Instructions in: `experiments/README.md` |
| Expected runtime |  |
| Expected output | All tests should pass with no failures. Ignored tests are expected as these are not relevent. |

## [4] Service Chain Expiration
| Item | Details |
| --- | --- |
| Supports | Service delegation chain for service grants should have an expiration, and generated tokens should have an expiry. |
| Command | Instructions in: `experiments/README.md` |
| Expected runtime |  |
| Expected output | All tests should pass with no failures. Ignored tests are expected as these are not relevent. |


## 5. Claims and limitations
### [1] Allowed Algorithms
__Claims__
- A token whose `alg` is not on the profile's list is rejected before any key is looked up.
- HS256/384/512 and `alg: none` are always rejected. A profile that lists one, or lists nothing, is invalid.
- External profiles allow RS256 and ES256 by default, and a configured list (PS256, EdDSA) also works.
- Keystone-native profiles allow only the configured algorithm.
- A key of the wrong type for the algorithm is rejected.
- A bad list gives `InvalidAlgorithmList`, and `InvalidProfile` is only for missing issuers or audiences.

__Limitations__
- The list is set in code, not per identity provider.
- Only `verify_subject_token_jwt` is covered. The federation login code (`verify_jwt`) is not changed.
- `verify_external_jwt` doesn't use these profiles yet. That is the next part of issue #1636.
- The wrong-key-type tests only check what the crypto library already does.
- #1639 is merged. #1642 is in review and could change.

### [2] Replay Cache
__Claims__
- A second use of the same `jti` from the same domain and issuer is refused while the entry is live.
- The same `jti` from another domain or issuer is not affected.
- An entry stays until `exp` plus 60 seconds, then the `jti` is accepted again.
- A full cache refuses new tokens and keeps live entries.
- One issuer can't use up the space of the others.
- The DPoP cache works as before.

__Limitations__
- Nothing calls the cache yet. The token endpoint still has to use it.
- It is in memory in one process, so each node has its own cache and a restart empties it. External tokens live at most 5 minutes, so the gap is small.
- Size limits are set in code, not read from the config.
- The maintainer added a `SingleUseStore` trait (#1641) after #1640 was opened. The cache should implement it, so #1640 will be reworked.
- A token without a `jti` can't be checked. Whether to reject those is not decided yet.
- #1640 is in review and could change.

### Functionality Tests We Contributed to the Testing Suites
#### Verify tests (#1639):
external_profile_defaults_to_rs256_and_es256
external_profile_accepts_configured_ps256
external_profile_accepts_configured_eddsa
external_profile_rejects_algorithm_outside_configured_list
external_profile_rejects_hs256_token
external_profile_rejects_alg_none_token
profile_never_allows_hmac_or_an_empty_list (renamed in #1642)
#### Verify tests (#1642):
profile_allows_only_public_key_algorithms_and_not_an_empty_list
external_profile_rejects_es256_token_against_an_rsa_only_jwks
external_profile_rejects_rs256_token_against_an_ec_only_jwks
#### Replay cache tests (#1640):
test_replay_rejected_and_other_id_or_scope_accepted
test_entry_dies_exactly_at_expires
test_scope_quota_does_not_evict
test_fresh_scope_flood_sheds_load_and_keeps_live_entries
test_expired_entries_free_room
test_reusing_expired_id_does_not_inflate_count
test_overwrite_allowed_at_quota
test_purge_expired
#### Assertion replay cache tests (#1640):
test_second_use_of_a_jti_is_refused
test_same_jti_is_independent_per_domain_and_issuer
test_scope_is_injective
test_entry_lives_until_exp_plus_skew
test_one_issuer_cannot_fill_the_cache
test_purge_expired
