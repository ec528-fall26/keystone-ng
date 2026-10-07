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

use jsonwebtoken::jwk::JwkSet;
use serde::Deserialize;

use crate::error::OidcError;

/// Subset of the OIDC provider metadata we use.
#[derive(Debug, Deserialize)]
pub struct OidcProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
}

/// Fetch `{issuer_url}/.well-known/openid-configuration`.
///
/// Per RFC 8414 §3 the returned `issuer` must match the URL used for discovery.
pub async fn discover(
    issuer_url: &str,
    client: &reqwest::Client,
) -> Result<OidcProviderMetadata, OidcError> {
    let base = issuer_url.trim_end_matches('/');
    let url = format!("{base}/.well-known/openid-configuration");
    let metadata = client
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json::<OidcProviderMetadata>()
        .await?;

    let returned_issuer = metadata.issuer.trim_end_matches('/');
    if returned_issuer != base {
        return Err(OidcError::IssuerMismatch {
            expected: base.to_string(),
            actual: returned_issuer.to_string(),
        });
    }

    Ok(metadata)
}

/// Fetch a JWKS from the given URI.
pub async fn fetch_jwks(jwks_uri: &str, client: &reqwest::Client) -> Result<JwkSet, OidcError> {
    let jwks = client
        .get(jwks_uri)
        .send()
        .await?
        .error_for_status()?
        .json::<JwkSet>()
        .await?;
    Ok(jwks)
}

/// HTTP client with redirects disabled and a 10s timeout.
pub fn build_http_client() -> Result<reqwest::Client, OidcError> {
    Ok(reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(10))
        .build()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::{TEST_JWK_E, TEST_JWK_N};
    use httpmock::prelude::*;
    use serde_json::json;

    fn discovery_doc(issuer: &str, base_url: &str) -> serde_json::Value {
        json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{base_url}/auth"),
            "token_endpoint": format!("{base_url}/token"),
            "jwks_uri": format!("{base_url}/jwks"),
        })
    }

    #[tokio::test]
    async fn discover_success() {
        let server = MockServer::start();
        let base_url = server.base_url();
        server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200)
                .json_body(discovery_doc(&base_url, &base_url));
        });

        let metadata = discover(&base_url, &reqwest::Client::new()).await.unwrap();
        assert_eq!(metadata.issuer, base_url);
        assert!(metadata.jwks_uri.ends_with("/jwks"));
    }

    #[tokio::test]
    async fn discover_strips_trailing_slash() {
        let server = MockServer::start();
        let base_url = server.base_url();
        server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200)
                .json_body(discovery_doc(&base_url, &base_url));
        });

        let with_slash = format!("{base_url}/");
        discover(&with_slash, &reqwest::Client::new())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn discover_errors_on_http_failure() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(404);
        });

        let result = discover(&server.base_url(), &reqwest::Client::new()).await;
        assert!(matches!(result, Err(OidcError::Http(_))));
    }

    #[tokio::test]
    async fn discover_rejects_issuer_mismatch() {
        let server = MockServer::start();
        let base_url = server.base_url();
        server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200)
                .json_body(discovery_doc("https://attacker.example.com", &base_url));
        });

        let result = discover(&base_url, &reqwest::Client::new()).await;
        assert!(matches!(result, Err(OidcError::IssuerMismatch { .. })));
    }

    #[tokio::test]
    async fn fetch_jwks_parses_key_set() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/jwks.json");
            then.status(200).json_body(json!({"keys": [{
                "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "k1",
                "n": TEST_JWK_N, "e": TEST_JWK_E,
            }]}));
        });

        let url = format!("{}/jwks.json", server.base_url());
        let jwks = fetch_jwks(&url, &reqwest::Client::new()).await.unwrap();
        assert_eq!(jwks.keys.len(), 1);
    }

    #[tokio::test]
    async fn fetch_jwks_errors_on_http_failure() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/jwks.json");
            then.status(500);
        });

        let url = format!("{}/jwks.json", server.base_url());
        let result = fetch_jwks(&url, &reqwest::Client::new()).await;
        assert!(matches!(result, Err(OidcError::Http(_))));
    }

    #[tokio::test]
    async fn http_client_does_not_follow_redirects() {
        let server = MockServer::start();
        server.mock(|when, then| {
            when.method(GET).path("/jwks.json");
            then.status(302)
                .header("location", "http://127.0.0.1:1/elsewhere");
        });

        let client = build_http_client().unwrap();
        let url = format!("{}/jwks.json", server.base_url());
        assert!(fetch_jwks(&url, &client).await.is_err());
    }
}
