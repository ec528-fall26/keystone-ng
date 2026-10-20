# Design Document

*Due in the `demo-2` branch, updated for `demo-3` and `final-demo`.
**The TA will run this document.** If they cannot follow it, you lose the points.*

## 1. Architecture

1. [Issue](https://github.com/openstack-experimental/keystone/issues/1353) :: [PR](https://github.com/openstack-experimental/keystone/pull/1459) :: Capped token lfietimes when exchanged to the earliest expiry of the credntial chain.
2. [Issue](https://github.com/openstack-experimental/keystone/issues/945) :: [PR](https://github.com/openstack-experimental/keystone/pull/1458) :: Added verification of external JWTs (signature, issuer and audience) so they can be used as the subject token in a token exchange.
3. [Issue](https://github.com/openstack-experimental/keystone/issues/1354) :: [PR](https://github.com/openstack-experimental/keystone/pull/1575) :: Added JWT subject-token-type validation and OAuth errors for missing or unsupported types.
## 2. Design decisions

1. Part of the OAuth2 implementation, when tokens are exchanged for new ones their lifetimes much be capped to the minimum of either the original token's expiry, or default expiry. In the current code, this lifetime is instead infinietly extened by the default lifetime (15 minutes), meaning everytime it is exchanged, its lifetime is extended by 15 minutes. This is a security concern as if an attacker acquires your token, they are then able to infinitely renew it to access sensitive data, resources, or conduct actions.

2. During the token exchange process, the subject token can be a JWT from an outside identity provider which can be faked very easily if no proper authentication method is carried out. Therefore, Keystone has to check it itself. We read the `iss` from the token and only keep proceeding with the authentication process if it found on the provided list of trusted issuers, else the process stops and nothing is fetched. 
   If the trusted issuer has a `jwks_url` we use it to get the keys, if not we use the discovery document that is already included the src code. The existing `verify_jwt` carry out the signature check which uses the issuer from our list, not the one in the token which prevent wrong verification. It also skips the audience check when no audience is given, so a token made for another service would be accepted without hard coding it to our specific implementation.
   Because of that our function returns an error if the audience list is empty. The untrusted issuer is not put in the error message, since the attacker controls that text and it would end up in the logs. The trusted list is given and stored in the `bound_issuer` of the identity provider.


## 3. Setup

Exact dependencies, versions, and hardware assumptions. Written so that someone
starting from a clean machine can follow it.

Rust will need to be installed on the machine. If using VSCode, instructions are able on the official website [here](https://code.visualstudio.com/docs/languages/rust).

1. Install the Rust tool chain [here](https://rustup.rs). This installer is for Windows, MacOS and Linux. 
2. Rust-Anlyzer is also avaliable on the VSCode extensions
3. Check if rust is installed: ```rustc --version```
4. Clone to Openstack Keystone fork repo: (This is our testing fork)
```
git clone https://github.com/millionsouls/keystone
```
5. Ensure you are on the demo-2 branch as this contains the proposed changes.
6. Keystone needs `protoc` to build. MacOS: ```brew install protobuf```. Ubuntu: ```sudo apt-get install protobuf-compiler pkg-config 
libssl-dev```.


## 4. Running the experiments
### Exchanged Token Lifetimes are Capped
| | |
| --- | --- |
| Supports | Exchanged token lifetimes' expiry should not exceed the total credential chain lifetime |
| Command | `experiments/<script>.sh` |
| Expected runtime | 3 minutes |
| Expected output | All tests should pass with no failures. Ignored tests are expected as these are not relevent to fix. |

### External JWT verification
| | |
| --- | --- |
| Supports | verify_external_jwt accepts a JWT from an issuer trusted through an identity provider's `bound_issuer` and rejects bad ones (PR #1458) |
| Command | `experiments/external-jwt-demo.sh` |
| Expected runtime | about 10 to 15 minutes the first time, most of it compiling Keystone |
| Expected output | 8 lines, `valid token` is ACCEPTED and the other 7 are REJECTED, then `65 passed; 0 failed`, and `12 passed; 0 failed` for the token exchange tests |

## 5. Claims and limitations

What your artifact supports, and an honest account of what does not work or was
not tested. *An honest narrower result scores better than an impressive result we
cannot reproduce.*

Works: a token from a trusted issuer with a good signature and audience is accepted. The tests check that bad ones are rejected: untrusted issuer, empty audience list, expired, wrong audience, wrong key, changed token, `alg: none` and HS256.

Not done: the token exchange endpoint only uses these functions in our patch (`src/external-jwt/4-token-exchange.patch`), not in PR #1458. The token it gives back only says who the external user is, it has no roles or project, since we did not map external users to Keystone users yet. The trusted issuers come from the `bound_issuer` of the enabled identity providers. `jwt_validation_pubkeys` is not used. We only tested with a mock identity provider, not a real one like Keycloak. The PR is still being reviewed so it can change.

