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

use thiserror::Error;

#[derive(Debug, Error)]
pub enum OidcError {
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("issuer mismatch: expected {expected}, got {actual}")]
    IssuerMismatch { expected: String, actual: String },

    #[error("jwt decode error: {source}")]
    JwtDecode {
        #[from]
        source: jsonwebtoken::errors::Error,
    },

    #[error("unsupported algorithm {0}")]
    UnsupportedAlgorithm(String),

    #[error("no JWK with kid {0}")]
    JwkNotFound(String),

    #[error("JWKS has no keys")]
    NoJwksKeys,

    #[error("nonce mismatch")]
    NonceMismatch,

    #[error("iat {iat} is too far in the future (now {now})")]
    IatInFuture { iat: u64, now: u64 },

    #[error("malformed token: {0}")]
    MalformedToken(String),

    #[error("token has no `iss` claim")]
    MissingIssuer,

    #[error("issuer `{0}` is not a trusted issuer")]
    UntrustedIssuer(String),
}
