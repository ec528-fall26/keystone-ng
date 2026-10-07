// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//! Verify external JWTs (RFC 8693 `subject_token`) against a trusted issuer's
//! JWKS, found through OIDC discovery.
//!
//! The discovery, JWKS and `verify_jwt` logic follows the helpers in
//! openstack-experimental/keystone (`federation/api/oidc_utils.rs`), so this
//! can be moved there later with little change.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

pub mod error;
pub mod oidc;
pub mod verify;

#[cfg(test)]
mod test_util;

pub use error::OidcError;
pub use verify::{extract_issuer, verify_external_jwt, verify_jwt};
