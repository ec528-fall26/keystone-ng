# Design Document

*Due in the `demo-2` branch, updated for `demo-3` and `final-demo`.
**The TA will run this document.** If they cannot follow it, you lose the points.*

## 1. Architecture

1. [Issue](https://github.com/openstack-experimental/keystone/issues/1353) :: [PR](https://github.com/openstack-experimental/keystone/pull/1459) :: Capped token lfietimes when exchanged to the earliest expiry of the credntial chain.
2. [Issue](https://github.com/openstack-experimental/keystone/issues/945) :: [PR](https://github.com/openstack-experimental/keystone/pull/1458) :: Added verification of external JWTs (signature, issuer and audience) so they can be used as the subject token in a token exchange.

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

4. Clone to Openstack Keystone repo: \
```
git clone https://github.com/openstack-experimental/keystone.git
```

## 4. Running the experiments

One entry per claim you make. Someone else runs these; you do not get to
explain them in person.

### Experiment 1: <the claim this supports>

| | |
| --- | --- |
| Supports | <which figure, table, or statement in your slides> |
| Command | `experiments/<script>.sh` |
| Expected runtime | <minutes> |
| Expected output | <what they should see, and what counts as a match> |

### Testing Exchanged Tokens Lifetimes are Capped

```cargo test -p openstack-keystone-core oauth2_client::token_exchange::tests``` Verifies expiry rules are in place

```cargo test -p openstack-keystone api::v4::oauth2::token::token_exchange::tests``` Pings token endpoints

```cargo check -p openstack-keystone --message-format=short``` Verifies everything complies together

```cargo fmt --check``` Ensures proper code format as part of Keystone contributer documents

## 5. Claims and limitations

What your artifact supports, and an honest account of what does not work or was
not tested. *An honest narrower result scores better than an impressive result we
cannot reproduce.*

Works: a token from a trusted issuer with a good signature and audience is accepted. The tests check that bad ones are rejected: untrusted issuer, empty audience list, expired, wrong audience, wrong key, changed token, `alg: none` and HS256.

Not done: nothing calls these functions yet, the token exchange endpoint only handles Keystone's own tokens. We did not decide where the trusted issuer list comes from. `jwt_validation_pubkeys` is not used. Only tested with a mock identity provider, not a real one like Keycloak. The PR is still in review so it can change.

