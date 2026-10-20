# Design Document

*Due in the `demo-2` branch, updated for `demo-3` and `final-demo`.
**The TA will run this document.** If they cannot follow it, you lose the points.*

## 1. Architecture

1. [Issue](https://github.com/openstack-experimental/keystone/issues/1353) :: [PR](https://github.com/openstack-experimental/keystone/pull/1459) :: Capped token lfietimes when exchanged to the earliest expiry of the credntial chain.
2. [Issue](https://github.com/openstack-experimental/keystone/issues/945) :: [PR](https://github.com/openstack-experimental/keystone/pull/1458) :: Added verification of external JWTs (signature, issuer and audience) so they can be used as the subject token in a token exchange.
3. [Issue](https://github.com/openstack-experimental/keystone/issues/1354) :: [PR](https://github.com/openstack-experimental/keystone/pull/1575) :: Added JWT subject-token-type validation and OAuth errors for missing or unsupported types.
4. [Issue](https://github.com/openstack-experimental/keystone/issues/1355) :: [PR](https://github.com/openstack-experimental/keystone/pull/1560) :: Added profile-driven JWT validation for OAuth2 subject tokens, providing a shared verification path for Keystone-native tokens and short-lived external assertions.

## 2. Design decisions
1. Part of the OAuth2 implementation, when tokens are exchanged for new ones their lifetimes much be capped to the minimum of either the original token's expiry, or default expiry. In the current code, this lifetime is instead infinietly extened by the default lifetime (15 minutes), meaning everytime it is exchanged, its lifetime is extended by 15 minutes. This is a security concern as if an attacker acquires your token, they are then able to infinitely renew it to access sensitive data, resources, or conduct actions.

2. During the token exchange process, the subject token can be a JWT from an outside identity provider which can be faked very easily if no proper authentication method is carried out. Therefore, Keystone has to check it itself. We read the `iss` from the token and only keep proceeding with the authentication process if it found on the provided list of trusted issuers, else the process stops and nothing is fetched. 
   If the trusted issuer has a `jwks_url` we use it to get the keys, if not we use the discovery document that is already included the src code. The existing `verify_jwt` carry out the signature check which uses the issuer from our list, not the one in the token which prevent wrong verification. It also skips the audience check when no audience is given, so a token made for another service would be accepted without hard coding it to our specific implementation.
   Because of that our function returns an error if the audience list is empty. The untrusted issuer is not put in the error message, since the attacker controls that text and it would end up in the logs. The trusted list is given and stored in the `bound_issuer` of the identity provider.

3. We validate `subject_token_type` before continuing token exchange. As an initial milestone, only the JWT type is accepted; missing or unsupported types return HTTP 400 with `invalid_request`. This gives clients clear errors while preserving existing authentication and delegation checks. Broader token-type dispatch required by upstream #1354 remains future work.

4. We add `SubjectTokenValidationProfile` and `verify_subject_token_jwt` for shared, profile-driven JWT validation. `verify_openstack_access_token` now uses the Keystone-native profile while retaining its revocation and delegation checks; external assertions can use stricter audience and lifetime rules. `SubjectTokenValidationProfile` defines the issuer, audience, required-claim, and time-validation rules for a subject-token type. `verify_subject_token_jwt` verifies a JWT’s signature and claims against those rules. `verify_openstack_access_token` now uses the Keystone-native profile while retaining its revocation and delegation checks.

## 3. Setup

Exact dependencies, versions, and hardware assumptions. Written so that someone
starting from a clean machine can follow it.

Rust will need to be installed on the machine. If using VSCode, instructions are able on the official website [here](https://code.visualstudio.com/docs/languages/rust).

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
5. Clone to Openstack Keystone fork repo: (This is our testing fork)
```
git clone https://github.com/millionsouls/keystone
```
6. Ensure you are on the demo-2 branch as this contains the proposed changes.
7. Keystone needs `protoc` to build. MacOS: ```brew install protobuf```. Ubuntu: ```sudo apt-get install protobuf-compiler pkg-config 
libssl-dev```.


## 4. Running the experiments
### Exchanged Token Lifetimes are Capped
| | |
| --- | --- |
| Supports | Exchanged token lifetimes' expiry should not exceed the total credential chain lifetime |
| Command | `experiments/README.md` |
| Expected runtime | Around 3-5 minutes depending on compile time based on hardware. |
| Expected output | All tests should pass with no failures. Ignored tests are expected as these are not relevent. |

### External JWT verification
| | |
| --- | --- |
| Supports | verify_external_jwt accepts a JWT from an issuer trusted through an identity provider's `bound_issuer` and rejects bad ones (PR #1458) |
| Command | `experiments/external-jwt-demo.sh` |
| Expected runtime | about 10 to 15 minutes the first time, most of it compiling Keystone |
| Expected output | 8 lines, `valid token` is ACCEPTED and the other 7 are REJECTED, then `65 passed; 0 failed`, and `12 passed; 0 failed` for the token exchange tests |

### Token-exchange request validation

| Item | Details |
| --- | --- |
| Supports | Rejects missing or unsupported token types while preserving existing token-exchange checks. |
| Command | `cargo test -p openstack-keystone --lib api::v4::oauth2::token::token_exchange::tests -j 1` |
| Expected runtime | Initial compilation may take several minutes; tests took approximately 0.26 seconds after compilation locally. |
| Expected output | On the updated `demo-2` branch: `17 passed; 0 failed`. |


## 5. Claims and limitations

### Token 
### JWT Validation
Works: a token from a trusted issuer with a good signature and audience is accepted. The tests check that bad ones are rejected: untrusted issuer, empty audience list, expired, wrong audience, wrong key, changed token, `alg: none` and HS256.

Not done: the token exchange endpoint only uses these functions in our patch (`src/external-jwt/4-token-exchange.patch`), not in PR #1458. The token it gives back only says who the external user is, it has no roles or project, since we did not map external users to Keystone users yet. The trusted issuers come from the `bound_issuer` of the enabled identity providers. `jwt_validation_pubkeys` is not used. We only tested with a mock identity provider, not a real one like Keycloak. The PR is still being reviewed so it can change.

