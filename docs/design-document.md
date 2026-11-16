# Design Document

*Due in the `demo-3` branch; updated for `demo-3` and `final-demo`.*

**The TA will run this document.** If they cannot follow it, you lose points.

## 1. Architecture

1. [Issue](https://github.com/openstack-experimental/keystone/issues/1636) :: [PR](https://github.com/openstack-experimental/keystone/pull/1639) :: Each token validation profile now has a list of allowed signing algorithms. External tokens accept RS256 and ES256 by default. HMAC and `alg: none` tokens are rejected. Merged. Code diff under: `src/demo-3/allowed-algorithms/1639.patch`
2. [Issue](https://github.com/openstack-experimental/keystone/issues/1636) :: [PR](https://github.com/openstack-experimental/keystone/pull/1642) :: Follow-up to #1639 for the maintainer's review: an allowlist instead of a banned list, a separate error for a bad list, and wrong-key-type tests. Code diff under: `src/demo-3/allowed-algorithms/1642.patch`
3. [Issue](https://github.com/openstack-experimental/keystone/issues/1636) :: [PR](https://github.com/openstack-experimental/keystone/pull/1640) :: A replay cache that remembers the `jti` of external tokens so the same token cannot be used twice. Code diff: `src/demo-3/replay-cache/1640.patch`.
4. [Issue](https://github.com/openstack-experimental/keystone/issues/1353) :: [PR](https://github.com/openstack-experimental/keystone/pull/1616) :: Follow-up to the previous token-expiration PR. Applies a default expiration when a token has none, rather than silently dropping the token or returning an error.
5. [No Direct Issue](https://github.com/openstack-experimental/keystone/issues/1353) :: [PR](https://github.com/openstack-experimental/keystone/pull/1645) :: At the project mentor's request, checks the service-grant chain and applies a default expiration to service grants. The expiration follows this priority: the grant's specific expiration, the client's `max_grant_lifetime`, and finally `default_access_lifetime`.
6. [Issue](https://github.com/openstack-experimental/keystone/issues/1354) :: [PR](https://github.com/openstack-experimental/keystone/pull/1575) :: Added RFC 8693 request validation to Keystone’s token exchange endpoint. Missing, empty, or unsupported subject token types return `invalid_request`, and successful responses include `issued_token_type`. Merged. Code diff: `src/demo-3/1575.patch`.
7. [Issue](https://github.com/openstack-experimental/keystone/issues/1366) :: [PR](https://github.com/openstack-experimental/keystone/pull/1646) :: Added a test fixture for user and service account JWTs from Keycloak. The full token exchange test in k3s is still in progress.
8. [Issues #1018 and #945](https://github.com/openstack-experimental/keystone/issues/1018) :: [PR](https://github.com/millionsouls/keystone/pull/10) :: Connected external JWT assertions to the RFC 8693 token-exchange endpoint. Keystone verifies assertions using trusted identity-provider configuration, maps their claims to an identity and authorization scope, and issues a scoped Keystone access token whose lifetime cannot exceed the assertion's expiry. The demo branch also integrates a cherry-picked snapshot of the replay cache from openstack-experimental/keystone#1640. This work was merged into the fork's `demo-3` branch; upstream merging is pending OpenStack collaborator review of the dependencies.

## 2. Design decisions
### 1. PR 1639/1642/1640
**Background.** A JWT has a header, claims, and a signature. The signature shows that the identity provider issued the token and that it has not been changed; the `alg` header specifies how it was signed.
- **RS256** is an RSA signature with SHA-256. The provider signs with a private key and Keystone checks with the public key.
- **ES256** is the same idea with an elliptic curve (ECDSA, P-256), so the keys and signatures are smaller.
- **HS256** uses one shared secret to sign and check. Keystone only has the provider's public key, so an attacker could use that public key as the secret and forge a token that passes. That is why HMAC is rejected.
1. The single `expected_algorithm` argument of `verify_subject_token_jwt` is removed, and each profile has a list of allowed algorithms. Keystone-native profiles allow only the configured signing algorithm. External profiles allow RS256 and ES256, and `with_allowed_algorithms` can change that. The `alg` in the header is checked against the list before any key is looked up. HMAC, `alg: none` and an empty list are rejected.
2. The maintainer asked for three changes in review, done in #1642. The HMAC check was a list of banned algorithms, so a new HMAC algorithm would get through. It is now a list of allowed ones (RS256/384/512, PS256/384/512, ES256/384, EdDSA). A bad list used `InvalidProfile`, whose message is about issuers and audiences, so it now has its own error, `InvalidAlgorithmList`. Tests were also added for a key of the wrong type (ES256 token with an RSA-only JWKS, RS256 token with an EC-only JWKS). The crypto library already rejects these, so no code changed. `crypto-inventory.md` is updated too.
3. An external token is valid for a few minutes, so a copied one could be used again. The replay cache stores each accepted `jti` per domain and issuer until `exp` plus the 60-second clock skew, and refuses it a second time. When full, it refuses new tokens and never deletes live entries. Otherwise, an attacker could flood it to push out a copied token's entry and replay it. The DPoP cache logic moved into a general `ReplayCache` that both `DpopReplayCache` and the new `AssertionReplayCache` use. The nine existing DPoP tests are unchanged.

### 2. Service Grants and Token Expirations
**Background.** Although permanent tokens (those without an expiry) are not technically prohibited by RFC guidelines, they can present significant security risks if not handled properly. We require all tokens to have an expiry. If a token has none, we apply a default limit of 15 minutes. This applies to both subject tokens and application credentials.

For applications, we focus on the service-grant chain, one of two delegation-chain types in Keystone. A service grant is like "giving permission in advance."

`User → create service-grant record → service redeems it → delegated access token`

An authenticated user creates a grant naming a service client, project, and role set. The roles must be within both the user’s effective roles and the client’s delegation ceiling (grant creation).

The service (e.g., Cinder) redeems the grant using the custom `urn:openstack:params:oauth:grant-type:service-grant` grant type. Redemption requires a matching SVID on the internal interface; Keystone rechecks the grant, grantor, and current roles (handler and core redemption). The token represents the user as `sub`, the service as `act`, and carries the grant and project in `delegation_context` (claim construction).

Essentially, a user tells Keystone, "Let this service act for me on this project, with these roles." The service then proves its identity using a SPIFFE certificate and asks Keystone for a short-lived access token. Keystone checks that the grant is still valid and that the user still has the relevant roles. The token says who the user is (`sub`) and which service is acting (`act`). The service can request another token later by redeeming the grant again. Revoking the grant prevents future redemptions, though already-issued tokens remain usable until they expire.

Permanent or overly long-lived service grants are dangerous because they violate the Principle of Least Privilege. Service tokens travel extensively across internal control plane networks to facilitate inter-service communication (e.g., Nova talking to Cinder or Neutron). If an internal control plane node is compromised, or if a service token accidentally leaks into debug logs or unencrypted databases, a permanent grant gives an attacker an indefinite, unexpiring key to cloud infrastructure.

### 3. RFC 8693 Token Exchange Validation
**Background.** In token exchange, `subject_token_type` tells Keystone what kind of token the client is sending, and `requested_token_type` tells Keystone what kind of token the client wants in return. Previously, Keystone read these fields without validating them. It also did not report the type of token issued in a successful response.

**Validate the token types.** The first version allowed the `jwt` subject token type for token exchange, but an existing API test sent `access_token`. I changed the handler to use an explicit match that preserves support for `access_token`, checks the Keystone-specific type, and retains the existing JWT compatibility path. A missing, empty, or unsupported subject type now returns HTTP 400 with `invalid_request`.

**Use the same rules across both exchange paths.** I added request validation for both standard and on-behalf-of flows. Keystone applies the per-client rate limit. Unsupported parameters now return errors that tell the client what went wrong. For example, an unsupported `resource` returns `invalid_target`.

**Tell the client what was issued.** Successful exchanges include `issued_token_type`, so the client can identify the type of token it received. I also added regression tests for invalid inputs and successful responses.

**Status.** [PR #1575](https://github.com/openstack-experimental/keystone/pull/1575) was merged upstream.

### 4. Keycloak Test Setup for Token Exchange

**Background.** Issue #1366 calls for testing token exchange with JWTs from a real identity provider. We need a test that obtains real input tokens from Keycloak for both a user and a client.

1. **Use an isolated Keycloak realm.** The test creates a temporary realm, obtains a user JWT using the password grant and a client-account JWT using `client_credentials`, and then deletes the realm. It runs without Selenium.
2. **Use the exact audience Keystone advertises.** The test uses Keystone’s advertised token endpoint as the sole audience for both JWTs. For example, if Keystone advertises `http://keystone-rs.local/v4/oauth2/default/token`, that exact URL must appear in `aud`. The test also checks the issuer, usernames, distinct subject and token IDs, and short token lifetimes.
3. **Make setup failures visible.** The test fails rather than silently skipping when it cannot reach Keystone.

**Status.** [PR #1646](https://github.com/openstack-experimental/keystone/pull/1646) is a draft. It prepares the inputs for #1366. 

### 5. External JWT exchange

**Background** Earlier contributions supplied JWT verification, mapping, request validation, and replay-cache components. This change connects those components so an external assertion can be exchanged for a Keystone access token.

1. **Preserve native-token validation.** JWT subjects first pass through the existing native validator. External verification is attempted only when the native driver cannot decode the token. A native token that fails authorization is not retried through another trust path.

2. **Trust the issuer before fetching keys.** Keystone uses the assertion's unverified `iss` only to select a configured identity provider within the requested domain. It then obtains keys from the provider's JWKS URL or OIDC discovery configuration and verifies the assertion using the shared external-assertion profile. The audience must match Keystone's exact token endpoint. Invalid assertions and DPoP-bound subject tokens are rejected.

3. **Match mapping rules before recording replay state.** Verified claims are flattened and evaluated against the issuer's enabled token-exchange mapping. The mapping must resolve one authorization scope, backed by valid resource records. Unmatched assertions do not consume replay-cache capacity.

4. **Record replay state before identity hydration.** After a mapping matches, Keystone records the assertion's domain, issuer, and `jti`. Only then does it hydrate the mapped identity, including federated-user creation and group synchronization where applicable, and construct a validated security context.

5. **Issue a new, bounded access token.** The token contains the mapped identity, effective roles, authorization scope, and mapping ruleset version. Its expiry is the earlier of the configured access-token expiry and the assertion's expiry. Keystone signs the token and emits a successful authentication audit event. The RFC 8693 response includes `issued_token_type`; this flow does not return an ID token or refresh token.

6. **Require explicit opt-in for the demo replay backend.** The demo integrates the process-local cache from openstack-experimental/keystone#1640. External exchange fails closed unless `allow_per_node_assertion_replay` is enabled. Replayed assertions are rejected; unavailable or exhausted replay protection returns HTTP 503. Cache entries are not shared across nodes and are lost on restart.

**Contribution boundary.** Commit `674904e6` supplies the demo-specific replay integration and native JWT compatibility changes. Commit `13ebc8b4` cherry-picks the collaborator's replay-cache implementation. These are separate from the original `oauth2-external-jwt-exchange` work and must be revisited when the upstream replay implementation is finalized. This split reflects the effort to develop a working end-to-end system while meeting rigorous review and testing requirements.

## 3. Setup
_Exact dependencies, versions, and hardware assumptions. Written so that someone
starting from a clean machine can follow it._

Rust must be installed on the machine. If you use VS Code, see the [official Rust documentation](https://code.visualstudio.com/docs/languages/rust).

1. Install the Rust toolchain using [rustup](https://rustup.rs). The installer supports Windows, macOS, and Linux.
2. The Rust Analyzer extension is available in the VS Code Marketplace.
3. Check that Rust is installed (this workspace requires Rust 1.96 or later):
   ```sh
   rustc --version
   cargo --version
   rustup show
   ```
4. The formatting and lint components can be installed or refreshed with:
   ```sh
   rustup component add rustfmt clippy
   ```
5. Clone the OpenStack Keystone fork (our testing fork). Our code is on the `demo-3` branch, so clone that branch:
   ```sh
   git clone -b demo-3 https://github.com/millionsouls/keystone.git
   cd keystone
   git branch --show-current
   ```
6. The last command should print `demo-3`.
7. Keystone needs `protoc` to build. On macOS, run `brew install protobuf`. On Ubuntu, run:
   ```sh
   sudo apt-get install protobuf-compiler pkg-config libssl-dev
   ```

## 4. Running the experiments
Run every command inside the fork clone from Setup (`millionsouls/keystone`, branch `demo-3`), not in this repo.

### [1] Allowed signing algorithms
| Item | Details |
| --- | --- |
| Supports | Algorithms not on the allowlist, HMAC, `alg: none`, and wrong key types are rejected (PRs #1639 and #1642). |
| Command | See `experiments/README.md`. |
| Expected runtime | 5 to 10 minutes on the first run (for compilation), then about 10 seconds. |
| Expected output | `9 passed; 0 failed` |

### [2] Replay cache
| Item | Details |
| --- | --- |
| Supports | The same `jti` is refused the second time, a full cache keeps live entries, and the DPoP cache works as before (PR #1640). |
| Command | See `experiments/README.md`. |
| Expected runtime | A few seconds, the build is already done by experiment [1]. |
| Expected output | `23 passed; 0 failed` (8 general cache, 6 assertion cache, 9 DPoP cache) |

### [3] Token Default Expiry
| Item | Details |
| --- | --- |
| Supports | A presented token with no expiry has a default expiration of 15 minutes applied. |
| Command | See `experiments/README.md`. |
| Expected runtime | A few minutes for the first compile; seconds afterward. |
| Expected output | All tests should pass with no failures. Ignored tests are expected and are not relevant. |

### [4] Service Chain Expiration
| Item | Details |
| --- | --- |
| Supports | Service delegation chain for service grants should have an expiration, and generated tokens should have an expiry. |
| Command | See `experiments/README.md`. |
| Expected runtime | A few minutes for the first compile; seconds afterward. |
| Expected output | All tests should pass with no failures. Ignored tests are expected and are not relevant. |
### [5] RFC 8693 token exchange validation

| Item | Details |
| --- | --- |
| Supports | Verifies that existing `access_token` requests still work, missing, empty, or unsupported `subject_token_type` values return `invalid_request`, and successful exchanges include `issued_token_type` (PR #1575). |
| Command | See `experiments/README.md`. |
| Expected runtime | The first run may take several minutes to compile. |
| Expected output | All matching tests pass with `0 failed`. |

### [6] Keycloak JWT Test Setup

Run this experiment on a checkout that contains draft PR #1646.

| Item | Details |
| --- | --- |
| Supports | Builds the test that prepares two kinds of JWTs from Keycloak: one for a user and one for a client account. The test checks that both tokens name Keystone’s exact token endpoint as their audience. |
| Command | `cargo test --locked -p test_federation --test keycloak_token_exchange --no-run` |
| Expected runtime | Depends on the build cache. |
| Expected output | Cargo builds the `keycloak_token_exchange` test executable. |
| Current status | Compilation passed, and a separate run confirmed that an unreachable Keystone causes a failure rather than a skip. |

### [7] External JWT exchange

| Item | Details |
| --- | --- |
| Supports | External assertion verification, identity mapping, issued-token claims and lifetime, replay rejection, fail-closed behavior, and replay configuration validation. |
| Instructions | Follow **External JWT Exchange** in [the experiments README](../experiments/README.md#external-jwt-exchange--millionsoulskeystone10). |
| Where to run | The root of the `millionsouls/keystone` fork checkout, branch `demo-3`. |
| Dependencies | Rust and the system build dependencies from Section 3. No running Keystone or Keycloak is required. |
| Expected runtime | Several minutes for an initial build; cached runs are substantially faster. |
| Expected output | All selected tests pass with `0 failed`. Verified on commit `7aab548f`: 8 handler tests, 1 token-lifetime test, and 1 configuration-validation test passed. |
| Limitations | Uses mocked providers and local HTTP fixtures. |


## 5. Claims and Limitations
### [1] Allowed Algorithms
**Claims**
- A token whose `alg` is not on the profile's list is rejected before any key is looked up.
- HS256/384/512 and `alg: none` are always rejected. A profile that lists one, or lists nothing, is invalid.
- External profiles allow RS256 and ES256 by default, and a configured list (PS256, EdDSA) also works.
- Keystone-native profiles allow only the configured algorithm.
- A key of the wrong type for the algorithm is rejected.
- A bad list gives `InvalidAlgorithmList`, and `InvalidProfile` is only for missing issuers or audiences.

**Limitations**
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

### [3] RFC 8693 Token Exchange Validation
**Claims**

- Keystone requires `subject_token_type`. A missing, empty, or unsupported value returns HTTP 400 with `invalid_request`.
- Both exchange flows apply the per-client rate limit before checking the exchange parameters.
- Unsupported resources return `invalid_target`, and unsupported scopes return `invalid_scope`.
- A successful exchange includes `issued_token_type`, so the client knows it received an access token.

**Limitations**

- Declaring `jwt` does not allow tokens from external identity providers. 
- The endpoint supports only the `openstack:api` scope for token exchange. Actor tokens and the `resource` parameter are not supported.
- Clients that previously omitted `subject_token_type` must now send it.
- PR #1575 was merged upstream.

### [4] Keycloak JWT Test Setup

**Claims**

- The fixture is designed to get two JWTs from Keycloak: one for a user and one for a client account.
- It checks that both tokens name Keystone’s exact `/token` URL as their only audience. It also checks the issuer, usernames, distinct subject and token IDs, and short lifetimes.
- The test target compiled. A separate run confirmed that an unreachable Keystone makes the test fail instead of skipping.

**Limitations**

- The live run with Keycloak in k3s is still pending, so successful JWT issuance in that environment has not been verified.
- The fixture does not submit the JWTs for exchange or check the resulting identities and roles.
- PR #1646 is a draft and does not complete #1366.

### [5] External JWT Exchange

**Claims**

- The demo connects external JWT verification, identity mapping, replay protection, and access-token issuance.
- Native JWT subjects retain the native validation path. Native authorization failures do not fall through to external verification.
- Identity providers are selected by issuer within the requested domain before fetching verification keys.
- Mapping evaluation precedes replay insertion; replay insertion precedes identity hydration.
- Issued tokens contain mapped identity information and effective roles, and cannot outlive the external assertion.
- External assertions require a valid expiry and non-empty `jti`.
- Focused tests cover successful exchange and rejection paths, including replay and unavailable replay protection.

**Limitations**

- The replay implementation is a cherry-picked development snapshot, not a finalized upstream dependency.
- External exchange requires explicit opt-in to process-local replay protection. Protection is neither shared across nodes nor retained across restarts.
- Identity providers configured only with `jwt_validation_pubkeys` are not supported by this exchange path; JWKS or discovery configuration is required.
- The exchange handler's external-assertion profile uses its configured defaults; this change does not add per-identity-provider algorithm configuration.
- The handler tests use mocked providers and local HTTP fixtures. The external-exchange success test inspects the minted token's claims but does not independently verify its signature.
- The Keycloak fixture remains separate: obtaining JWTs does not demonstrate their successful exchange or downstream API acceptance.

### [6] Service Grants and Token Expiration
Service grants and issued tokens should all have an expiration time. Service-grant expiration should first use any user-applied expiration, then any preconfigured `max_access_lifetime` set by the client, and finally the default lifetime stated in `Config.oauth2` in `lib.rs`.

All OAuth 2.0 tokens, subject tokens, and application credentials require an `expire_at` field. If none is provided, a default of 15 minutes is applied. Whether configured or defaulted, the lifetime must be in the future so that the token does not expire immediately upon issuance. If more than one valid lifetime is available, the shortest one is used.

### Functionality Tests Contributed to the Test Suites
#### Verification tests (#1639)
- `external_profile_defaults_to_rs256_and_es256`
- `external_profile_accepts_configured_ps256`
- `external_profile_accepts_configured_eddsa`
- `external_profile_rejects_algorithm_outside_configured_list`
- `external_profile_rejects_hs256_token`
- `external_profile_rejects_alg_none_token`
- `profile_never_allows_hmac_or_an_empty_list` (renamed in #1642)

#### Verification tests (#1642)
- `profile_allows_only_public_key_algorithms_and_not_an_empty_list`
- `external_profile_rejects_es256_token_against_an_rsa_only_jwks`
- `external_profile_rejects_rs256_token_against_an_ec_only_jwks`

#### Replay-cache tests (#1640)
- `test_replay_rejected_and_other_id_or_scope_accepted`
- `test_entry_dies_exactly_at_expires`
- `test_scope_quota_does_not_evict`
- `test_fresh_scope_flood_sheds_load_and_keeps_live_entries`
- `test_expired_entries_free_room`
- `test_reusing_expired_id_does_not_inflate_count`
- `test_overwrite_allowed_at_quota`
- `test_purge_expired`

#### Assertion replay-cache tests (#1640)
- `test_second_use_of_a_jti_is_refused`
- `test_same_jti_is_independent_per_domain_and_issuer`
- `test_scope_is_injective`
- `test_entry_lives_until_exp_plus_skew`
- `test_one_issuer_cannot_fill_the_cache`
- `test_purge_expired`

#### Token exchange handler tests — PR #1575 (merged)

- `test_token_exchange_accepts_access_token_subject_type` — checks that an existing `access_token` request still works.
- `test_token_exchange_accepts_keystone_subject_type` — checks that the Keystone-specific token type is accepted.
- `test_token_exchange_missing_subject_token_type_is_invalid_request` — checks that omitting the type returns `invalid_request`.
- `test_token_exchange_empty_subject_token_type_is_invalid_request` — checks that `subject_token_type=` returns `invalid_request`.
- `test_token_exchange_unsupported_subject_token_type_is_invalid_request` — checks that an unknown type returns `invalid_request`.
- `test_token_exchange_rate_limit_precedes_subject_token_type_validation` — checks that rate limiting runs before type validation.
- `test_token_exchange_rejects_actor_token`, `test_token_exchange_rejects_actor_token_type`, and `test_token_exchange_rejects_resource_even_if_empty_or_repeated` — check that unsupported parameters are rejected.
- `test_token_exchange_rejects_unsupported_scope_without_issuing_token` — checks that an unsupported scope does not result in a new token.

#### Token exchange API tests — PR #1575 (merged)

- `test_token_exchange_success_with_jwt_type` and `test_token_exchange_success_with_keystone_type` — cover successful exchange through the existing Keystone validation path.
- `test_token_exchange_requires_subject_token_type` and `test_token_exchange_rejects_unsupported_subject_token_type` — check that the HTTP API rejects missing and unsupported types.
- `test_token_exchange_rejects_unsupported_rfc8693_parameters` — checks rejection of unsupported request parameters at the API level.
- `test_token_exchange_accepts_requested_output_type_and_scope` — checks that a valid request succeeds and the response reports the issued token type and scope.

#### External JWT exchange tests — millionsouls/keystone#10

- `issuer_extraction_only_selects_a_candidate` — checks that issuer extraction selects a candidate provider rather than establishing trust.
- `production_handler_fails_closed_before_mapping_without_replay_cache` — checks that unavailable replay protection blocks exchange before mapping.
- `external_exchange_verifies_maps_mints_claims_and_rejects_replay` — exercises external dispatch, verification, mapping, issued claims and expiry, then rejects reuse of the assertion.
- `external_exchange_rejects_untrusted_issuer_before_mapping` — rejects an issuer without a trusted provider.
- `external_exchange_rejects_bad_signatures_audiences_and_expired_tokens` — rejects invalid signatures, incorrect audiences, and expired assertions.
- `unmatched_mapping_does_not_consume_replay_capacity` — verifies that missing mappings neither hydrate identities nor consume replay-cache entries.
- `replay_cache_quota_errors_fail_closed` — checks that replay-capacity errors produce HTTP 503 rather than allowing exchange.
- `identity_provider_discovery_resolves_jwks` — checks JWKS resolution through a local OIDC discovery fixture.
- `external_token_expiry_never_exceeds_assertion_expiry` — checks both expiry ceilings and rejection when no positive lifetime remains.

These tests cover the demo integration. They do not constitute a live external identity provider system test.

#### Keycloak test setup — PR #1646 (draft)

- `keycloak_issues_user_and_service_account_subjects` — prepares a user JWT and a service account JWT from Keycloak. It checks that both tokens name Keystone’s exact token endpoint as their audience and have distinct subject and token IDs.
- The test compiled, and an unreachable Keystone caused it to fail rather than skip. The live k3s run is still pending. This test does not yet submit either JWT for exchange.
