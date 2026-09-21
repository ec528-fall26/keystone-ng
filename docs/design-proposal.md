# Design Proposal

*Due in the `demo-1` branch at 12:00 noon on 09/23. This document is what your
progress is graded against for the rest of the semester — see the
[progress rubric](https://ec528.github.io/ec528/fall26/grading/#progress).*

## 1. Problem

Currently, Openstack Keystone utilizes Python for identiy and authenticaiton fucntionality. While Python has its advantages, introducing modern authentication methods such as OAuth2 and OIDC can be challenging due to sensitive protocls, performance requirments, and integration with existing services. This project aims to explore the Rust programming language as an alternative to address these challenges while still being compatiblity with existing Openstack services. 

OpenStack Keystone is the primary tool for identity verification and access authorization in OpenStack. Keystone is responsible for verifying request into its service including authentication, authorization and the user' scope. As such, it is a critical component of the service as its failure can result in illegitimate user access to cloud resources and accidentally granting access to sensitive information.

The current Python Keystone implementation is reliable and widely used. Nevertheless, it lacks several modern authentication methods as well as being more limited in performance, concurrency and its maintainability from legacy code and dependencies. For future developments, accumulating legacy code debts and redundant dependencies can often be substantial hurdle both for maintaining as well as continued service development.

A new Rust-based Keystone branch is being developed which aims to be deployed side by side with the current Python Keystone, allowing for seamless integration and performance improvements without disrupting the current operational version. The project aims to implement a fully compliant RFC 8693 OAuth 2.0 Token Exchange mechanism within the Rust branch. This will replace the non-compliant method of exchanging external IdP JWTs for Keystone tokens, ensuring secure, standards-based identity federation.


## 2. Proposed design

Our project doesn't have a "design" per se, as the system already exists. Instead, we have a list of features that need to be implemented in Keystone. Each feature will require a different design and implementation approach, depending on the requirements, resources, and technical considerations involved. At the moment, we are planning to implement the RFC-8693 token exchange. To do this efficiently, we will reuse the existing grant-agnostic mapping engine (authenticate_by_mapping and evaluate_ruleset). The implementation requires adding a new branch on the /token endpoint dispatch that handles grant_type=token-exchange and discriminates based on the subject_token_type being an external JWT (urn:ietf:params:oauth:token-type:jwt) rather than creating a parallel endpoint.   Once the request is routed, the system will verify the external token's signature against a trusted-issuer JWKS. We will then flatten the verified claims into a HashMap, create a new IdentitySource::TokenExchange variant, and pass it through the existing pipeline to hydrate the security context and mint the OpenStack access token identical to every other ingress path. 


## 3. What makes this hard

As Openstack is an industry level software the difficulty comes from ensure this coding meets the standards for use by not only a multilde of scenarios, companies, and user cases. But also compatible with the variety of Openstack services. Another challenge is correctly implementing security-sensitive protocols. OAuth 2.0 and OIDC involve security critical operations such as token issuance and validation, client authentication, cryptographic verification, expiration handling, scopes, and protection against common authentication attacks. Small implementation errors can have significant consequences, so the implementation must follow protocol specifications and OpenStack's security requirements rather than simply implementing a basic version of the protocol. These functions and protocols must then be peer reviewed and checked by contributors of Openstack, and revelent personnel before implementation.

## 4. How you will know it worked

We will know it worked when an automated test harness can successfully submit an external IdP JWT (e.g., from Okta or Google) to the Rust Keystone /token endpoint and receive a valid OpenStack access token in exchange. Specifically, the tests must prove that:   The endpoint successfully parses the grant_type=token-exchange and routes the request based on the subject_token_type.   The new validation profile correctly verifies the external JWKS signature and explicitly rejects tokens with invalid audiences or replayed jti claims.   The external claims are successfully mapped to OpenStack roles using the existing evaluate_ruleset and authenticate_by_mapping pipeline. 

## 5. Milestones

**Milestones must be verifiable.** A milestone is verifiable if a reader can tell,
without asking you, whether it is done. "Improve performance" is not verifiable;
"end-to-end write latency under 50 ms at 1k req/s, measured by
`experiments/latency.sh`" is.

| Demo | Date | Milestone | How we will demonstrate it |
| --- | --- | --- | --- |
| Demo 2 | 10/21 | | |
| Demo 2 | 10/21 | | |
| Demo 3 | 11/16 | | |
| Demo 3 | 11/16 | | |
| Final | 12/09 | | |

*You may revise these later — real projects change direction. Announce the change
and its justification at the demo and you are graded against the revised plan.
Silently dropping a milestone counts as a miss.*

## 6. Risks

Risk 1: Breaking existing validation. Refactoring verify.rs from a hardcoded constant to a per-subject profile might inadvertently break existing Keystone-native app credential flows.   

Mitigation 1: Write extensive regression tests for the current behavior of verify.rs before introducing the dynamic profile, ensuring 100% backward compatibility for internal Keystone tokens.

Risk 2: Performance bottlenecks with jti caching. Implementing stateful caching for the jti mitigation against replay attacks could introduce high-latency database locks under heavy load.   

Mitigation 2: Leverage a fast, lock-free, TTL-based in-memory cache (e.g., Redis or an async Rust equivalent) strictly tailored for short-lived assertions. 

## 7. Sources

https://github.com/openstack-experimental/keystone/issues/945 

Guidance from https://gemini.google.com/
