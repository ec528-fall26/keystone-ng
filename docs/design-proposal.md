# Design Proposal

*Due in the `demo-1` branch at 12:00 noon on 09/23. This document is what your
progress is graded against for the rest of the semester — see the
[progress rubric](https://ec528.github.io/ec528/fall26/grading/#progress).*

## 1. Problem

Currently, Openstack Keystone utilizes Python for identiy and authenticaiton fucntionality. While Python has its advantages, introducing modern authentication methods such as OAuth2 and OIDC can be challenging due to sensitive protocls, performance requirments, and integration with existing services. This project aims to explore the Rust programming language as an alternative to address these challenges while still being compatiblity with existing Openstack services. 

OpenStack Keystone is the primary tool for identity verification and access authorization in OpenStack. Keystone is responsible for verifying request into its service including authentication, authorization and the user' scope. As such, it is a critical component of the service as its failure can result in illegitimate user access to cloud resources and accidentally granting access to sensitive information.

The current Python Keystone implementation is reliable and widely used. Nevertheless, it lacks several modern authentication methods as well as being more limited in performance, concurrency and its maintainability from legacy code and dependencies. For future developments, accumulating legacy code debts and redundant dependencies can often be substantial hurdle both for maintaining as well as continued service development.

A new Rust-based Keystone branched is being developed which aims to be deployed side by side with the current Python Keystone, allowing for seamless integration and performance improvements without disrupting the current operational version. The project aims to mTLS+Webauthn (RFC 8705) authentication method and OAuth2 token exchange function.


## 2. Proposed design

Our project doesn't have a "design" per se, as the system already exists. Instead, we have a list of features that need to be implemented in Keystone. Each feature will require a different design and implementation approach, depending on the requirements, resources, and technical considerations involved. At the moment, we are planning to work on OAuth 2.0 Client Credentials support. This allows a client to obtain an OAuth 2.0 access token from Keystone and use it to access protected OpenStack service APIs on behalf of a user, without requiring a browser-based login flow for each API interaction. Keystone middleware can then validate the access token and provide the relevant user and authorization context to the OpenStack service.


## 3. What makes this hard

As Openstack is an industry level software the difficulty comes from ensure this coding meets the standards for use by not only a multilde of scenarios, companies, and user cases. But also compatible with the variety of Openstack services. Another challenge is correctly implementing security-sensitive protocols. OAuth 2.0 and OIDC involve security critical operations such as token issuance and validation, client authentication, cryptographic verification, expiration handling, scopes, and protection against common authentication attacks. Small implementation errors can have significant consequences, so the implementation must follow protocol specifications and OpenStack's security requirements rather than simply implementing a basic version of the protocol. These functions and protocols must then be peer reviewed and checked by contributors of Openstack, and revelent personnel before implementation.

## 4. How you will know it worked



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

What could stop you, and what you will do about it.
