# Design Document

*Due in the `demo-2` branch, updated for `demo-3` and `final-demo`.
**The TA will run this document.** If they cannot follow it, you lose the points.*

## 1. Architecture

1. [Issue](https://github.com/openstack-experimental/keystone/issues/1353) :: [PR](https://github.com/openstack-experimental/keystone/pull/1459) :: Capped token lfietimes when exchanged to the earliest expiry of the credntial chain. Code diff under: `src/expiry-lifetime/expity.patch` 
2. [Issue](https://github.com/openstack-experimental/keystone/issues/945) :: [PR](https://github.com/openstack-experimental/keystone/pull/1458) :: Added verification of external JWTs (signature, issuer and audience) so they can be used as the subject token in a token exchange. The code is on the `demo-2` branch of our fork. Patches against upstream: `src/external-jwt/`.
3. [Issue](https://github.com/openstack-experimental/keystone/issues/1354) :: [PR](https://github.com/openstack-experimental/keystone/pull/1575) :: Added JWT subject-token-type validation and OAuth errors for missing or unsupported types.
4. [Issue](https://github.com/openstack-experimental/keystone/issues/1355) :: [PR](https://github.com/openstack-experimental/keystone/pull/1560) :: Added profile-driven JWT validation for OAuth2 subject tokens, providing a shared verification path for Keystone-native tokens and short-lived external assertions.

## 2. Design decisions

1. Previously, each token exchange issued a token expiring at now + access_token_lifetime_minutes (15 minutes by default), regardless of the subject token's expiry. Because an exchanged token could be exchanged again, an attacker holding one token could renew it indefinitely. The issued token's expiry is now the minimum of the configured lifetime, the subject token's expiry, and the delegated application credential's expiry, if it has one. The subject token's expiry is required, so a missing one is rejected with invalid_grant. The credential's expiry is optional, since application credentials may be non-expiring, and a missing one simply adds no extra cap. If the capped expiry is at or before the issue time, the request is also rejected with invalid_grant.

2. During the token exchange process, the subject token can be a JWT from an outside identity provider which can be faked very easily if no proper authentication method is carried out. Therefore, Keystone has to check it itself. We read the `iss` from the token and only keep proceeding with the authentication process if it found on the provided list of trusted issuers, else the process stops and nothing is fetched. 
   If the trusted issuer has a `jwks_url` we use it to get the keys, if not we use the discovery document that is already included the src code. The existing `verify_jwt` carry out the signature check which uses the issuer from our list, not the one in the token which prevent wrong verification. It only allows asymmetric algorithms, so HS256 and `alg: none` tokens are rejected. It also skips the audience check when no audience is given, so a token made for another service would be accepted without hard coding it to our specific implementation.
   Because of that our function returns an error if the audience list is empty. The untrusted issuer is not put in the error message, since the attacker controls that text and it would end up in the logs. The trusted list is given and stored in the `bound_issuer` of the identity provider, and only enabled providers count. The audience has to be the `client_id` of the client doing the exchange. A JWT from an issuer that is not on the list is treated as a normal Keystone token and rejected there.

3. We validate `subject_token_type` before continuing token exchange. As an initial milestone, only the JWT type is accepted; missing or unsupported types return HTTP 400 with `invalid_request`. This gives clients clear errors while preserving existing authentication and delegation checks. Broader token-type dispatch required by upstream #1354 remains future work.

4. We add `SubjectTokenValidationProfile` and `verify_subject_token_jwt` for shared, profile-driven JWT validation. `verify_openstack_access_token` now uses the Keystone-native profile while retaining its revocation and delegation checks; external assertions can use stricter audience and lifetime rules. `SubjectTokenValidationProfile` defines the issuer, audience, required-claim, and time-validation rules for a subject-token type. `verify_subject_token_jwt` verifies a JWT’s signature and claims against those rules. `verify_openstack_access_token` now uses the Keystone-native profile while retaining its revocation and delegation checks.

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
5. Clone to Openstack Keystone fork repo: (This is our testing fork). Our code is on the `demo-2` branch, so clone that branch:
```
git clone -b demo-2 https://github.com/millionsouls/keystone.git
cd keystone
git branch --show-current
```
6. The last command should print `demo-2`.
7. Keystone needs `protoc` to build. MacOS: ```brew install protobuf```. Ubuntu: ```sudo apt-get install protobuf-compiler pkg-config 
libssl-dev```.


## 4. Running the experiments
Run every command inside the fork clone from Setup (`millionsouls/keystone`, branch `demo-2`), not in this repo.

### [1] Token Lifetime Expiry Cap
| Item | Details |
| --- | --- |
| Supports | Exchanged token lifetimes' expiry should not exceed the total credential chain lifetime |
| Command | Instructions in: `experiments/README.md` |
| Expected runtime | Around 3-5 minutes depending on compile time based on hardware. |
| Expected output | All tests should pass with no failures. Ignored tests are expected as these are not relevent. |

### [2] External JWT verification
| Item | Details |
| --- | --- |
| Supports | `verify_external_jwt` accepts a JWT from an issuer trusted through an identity provider's `bound_issuer` and rejects bad ones (PR #1458). The token exchange uses it for JWTs from those providers. |
| Command | Instructions in: `experiments/README.md` |
| Expected runtime | About 5 to 10 minutes the first time (compiling Keystone), a few seconds after that. |
| Expected output | A table of 8 tokens, `valid token` is ACCEPTED and the other 7 are REJECTED, then `1 passed; 0 failed`. Then the token exchange tests end with `17 passed; 0 failed` and the last line is `OK: demo passed and all 17 token exchange tests passed.` |

All the JWT verification tests: `cargo test -p openstack-keystone --lib federation::api::oidc_utils`, should end with `65 passed; 0 failed`.

### [3] Token-exchange request validation

| Item | Details |
| --- | --- |
| Supports | Rejects missing or unsupported token types while preserving existing token-exchange checks. |
| Command | `cargo test -p openstack-keystone --lib api::v4::oauth2::token::token_exchange::tests -j 1` |
| Expected runtime | Initial compilation may take several minutes; tests took approximately 0.26 seconds after compilation locally. |
| Expected output | On the updated `demo-2` branch: `17 passed; 0 failed`. |

### [4] Validation Profile for OAuth2 subject tokens

| Item | Details |
| --- | --- |
| Supports | `SubjectTokenValidationProfile` configures JWT validation rules by subject-token type; `verify_subject_token_jwt` validates signature, issuer, audience, required claims, and timing. `verify_openstack_access_token` reuses the Keystone-native profile while retaining revocation and delegation checks |
| Command | Instructions in: `experiments/README.md` |
| Expected runtime | ~5 minutes |
| Expected output | On the updated `demo-2` branch: `46 passed; 0 failed` for verifier tests. |

### [5] Conform with contributor and security expectations

| Item | Details |
| --- | --- |
| Supports | Catching common mistakes, optimizing code, enforcing style guidelines, verifing everything complies together and assures proper code format as part of Keystone contributer documents |
| Command | Instructions in: `experiments/README.md` |
| Expected runtime | ~10 minutes |
| Expected output | 6 warnings and 0 failures. Please note that these warnings are in regards to unused code which we did not contribute. |


## 5. Claims and limitations

### [1] Token Lifetime Expiry Cap
__Claims__
- An exchanged token never outlives its subject token.
- An exchanged token never outlives the application credential it was delegated from, when that credential has an expiry.
- An exchanged token never exceeds the configured access token lifetime.
- Re-exchanging an exchanged token cannot extend its lifetime beyond the original bounds.

__Limitations__
- A non-expiring application credential is still a long-lived credential. This change bounds each exchanged token, not the credential. Anyone who can obtain a fresh subject token from it can keep getting new exchanged tokens.
- Only application credential delegation is supported. Trust and EC2 return UnsupportedDelegation. The interface is built to extend, but a delegation with several expiries would need to return the earliest one.
- The cap relies on the caller passing credential_expiration. Passing None skips the credential cap silently. The integration test that asserts exp equals the credential's expiry guards against this.
- The expired-subject HTTP test mocks token validation. It exercises the defense-in-depth path in claim building. In production, token validation would typically reject an expired subject token earlier.
- MissingSubjectTokenExpiry is covered at the core level, not over HTTP. Covering it over HTTP needs a test helper that can build a subject token without an expiry.

### [2] JWT Validation
Works: a token from a trusted issuer with a good signature and audience is accepted. The tests check that bad ones are rejected: untrusted issuer, empty audience list, expired, wrong audience, wrong key, changed token, `alg: none` and HS256.

Not done: PR #1458 does not call these functions. The token exchange only uses them in our fork on the `demo-2` branch (same change against upstream: `src/external-jwt/4-token-exchange.patch`). The token it gives back only says who the external user is, with no roles or project, since we did not map external users to Keystone users yet. It also gets the default lifetime and is not capped to the expiry of the external JWT, so it can outlive it (the cap in [1] only covers Keystone tokens). The trusted issuers come from the `bound_issuer` of the enabled identity providers. `jwt_validation_pubkeys` is not used. We only tested with a mock identity provider, not a real one like Keycloak. The PR is still being reviewed so it can change.

### [4] Validation Profiles

__Claims and Limitations__
- Adds SubjectTokenValidationProfile to define issuer, audience, required-claim, and time-validation rules for different JWT subject-token types.
- Adds verify_subject_token_jwt to validate a JWT’s signature and claims against a profile.
- Refactors verify_openstack_access_token to use the Keystone-native profile while retaining revocation and delegation checks.
- Adds focused tests for valid and rejected tokens, including signature, issuer, audience, claims, and timing checks.
- Does not wire external JWT verification into the token-exchange endpoint.
- Does not fetch external issuer keys, implement replay prevention, or integrate the mapping engine.
### [5] Subject Token Type Validation

**Claims**

- Token-exchange requests require the include `subject_token_type`.
- It only accepts `urn:ietf:params:oauth:token-type:jwt`as the requirement token class.
- Missing or unsupported types return HTTP 400 with the OAuth `invalid_request` error.
- Two new negative tests about missing and unsupported types. All 11 targeted tests passed on the feature branch. 
**Limitations**

- This checks the declared token type, it not really check the format, signature, issuer, or audience of token. Those checks will vaildate on the downstream verifier.
- JWT-only acceptance is an initial milestone. It does not implement the broader token-type dispatch required by upstream issue #1354.
- This change does not met other RFC 8693 requirements,  `requested_token_type` and `issued_token_type`, or scope handling still need time to solve.
- Passing the targeted tests does not establish full project compatibility. The broader Tempest run reported failures that still need investigation.
- PR #1575 was submitted upstream; submission does not mean the change has been accepted or merged.
### Functionality Tests We Contributed to the Testing Suites
#### In core token-exchange tests:
test_build_token_exchange_claims_caps_at_subject_token_expiry
test_build_token_exchange_claims_caps_at_app_credential_expiry
test_build_token_exchange_claims_uses_default_when_credentials_live_longer
test_build_token_exchange_claims_rejects_missing_subject_expiry
test_build_token_exchange_claims_rejects_expiry_equal_to_iat
test_build_token_exchange_claims_skips_app_credential_term_without_expiry
test_build_token_exchange_claims_rejects_non_positive_lifetime
#### In token-exchange handler tests:
test_token_exchange_rejects_already_expired_app_cred
test_token_exchange_rejects_app_cred_expiring_now
test_token_exchange_rejects_expired_subject_token
#### In integration tests:
test_token_exchange_caps_expiry_at_short_lived_app_credential
#### In OIDC utility tests:
extract_issuer_returns_iss_claim
extract_issuer_does_not_verify_signature
extract_issuer_rejects_missing_or_non_string_iss
extract_issuer_rejects_malformed_tokens
extract_issuer_rejects_alg_none
verify_external_jwt_accepts_valid_token
verify_external_jwt_requires_exact_issuer_match
verify_external_jwt_rejects_untrusted_issuer_without_network_io
verify_external_jwt_untrusted_issuer_is_not_logged
verify_external_jwt_rejects_empty_trusted_list
verify_external_jwt_rejects_empty_audiences
verify_external_jwt_prefers_static_jwks_url_over_discovery
verify_external_jwt_rejects_tampered_payload
verify_external_jwt_rejects_tampered_signature
verify_external_jwt_rejects_signature_from_other_key_under_trusted_kid
verify_external_jwt_rejects_unknown_kid
verify_external_jwt_rejects_discovery_issuer_mismatch
verify_external_jwt_rejects_expired_token
verify_external_jwt_rejects_wrong_audience
verify_external_jwt_rejects_symmetric_algorithm
verify_external_jwt_propagates_jwks_fetch_failure
trusted_issuers_from_idps_uses_enabled_providers_with_bound_issuer
demo_external_jwt_verification
#### In token-exchange handler tests:
test_token_exchange_accepts_jwt_from_bound_issuer
test_token_exchange_rejects_external_jwt_for_other_client
#### In token-exchange handler tests:
test_token_exchange_missing_subject_token_type_is_invalid_request
test_token_exchange_unsupported_subject_token_type_is_invalid_request
test_token_exchange_rejects_jwt_from_untrusted_issuer
#### In verify tests:
subject_token_profile_accepts_short_lived_assertion
subject_token_profile_rejects_bad_signature_and_algorithm
subject_token_profile_rejects_untrusted_issuer
subject_token_profile_requires_exact_endpoint_audience
subject_token_profile_requires_jti
subject_token_profile_enforces_maximum_lifetime_and_age
subject_token_profile_rejects_empty_issuer_allowlist
test_service_grant_scope_drift_tripwire_trips

