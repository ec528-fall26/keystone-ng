# Design Document

*Due in the `demo-2` branch, updated for `demo-3` and `final-demo`.
**The TA will run this document.** If they cannot follow it, you lose the points.*

## 1. Architecture

1. [Issue](https://github.com/openstack-experimental/keystone/issues/1353) :: [PR](https://github.com/openstack-experimental/keystone/pull/1459) :: Capped token lfietimes when exchanged to the earliest expiry of the credntial chain.
2. 


## 2. Design decisions

1. Part of the OAuth2 implementation, when tokens are exchanged for new ones their lifetimes much be capped to the minimum of either the original token's expiry, or default expiry. In the current code, this lifetime is instead infinietly extened by the default lifetime (15 minutes), meaning everytime it is exchanged, its lifetime is extended by 15 minutes. This is a security concern as if an attacker acquires your token, they are then able to infinitely renew it to access sensitive data, resources, or conduct actions.

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
