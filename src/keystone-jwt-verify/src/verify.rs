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

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{
    Algorithm, DecodingKey, Header, TokenData, Validation, decode, decode_header, jwk::JwkSet,
};

use crate::error::OidcError;
use crate::oidc::{discover, fetch_jwks};

/// Maximum allowed `iat` skew in seconds (OIDC Core §3.2.1.1).
const IAT_FUTURE_MAX_SECS: u64 = 3600;

/// Asymmetric algorithms only. HMAC is rejected so a public key can never be
/// used as an HMAC secret.
fn is_asymmetric(alg: Algorithm) -> bool {
    matches!(
        alg,
        Algorithm::RS256
            | Algorithm::RS384
            | Algorithm::RS512
            | Algorithm::ES256
            | Algorithm::ES384
            | Algorithm::PS256
            | Algorithm::PS384
            | Algorithm::PS512
            | Algorithm::EdDSA
    )
}

/// Decode and verify a JWT against a JWKS.
///
/// - `issuer`: checks `iss` when `Some`.
/// - `expected_nonce`: checks `nonce` when `Some`.
/// - `audiences`: checks `aud` when non-empty.
///
/// Returns the verified claims.
pub fn verify_jwt(
    token: &str,
    jwks: &JwkSet,
    issuer: Option<&str>,
    expected_nonce: Option<&str>,
    audiences: &[&str],
) -> Result<serde_json::Value, OidcError> {
    let header: Header = decode_header(token)?;

    if !is_asymmetric(header.alg) {
        return Err(OidcError::UnsupportedAlgorithm(format!("{:?}", header.alg)));
    }

    // Pick the key by kid; without a kid, try every key in the set.
    let decoding_key = if let Some(kid) = &header.kid {
        let jwk = jwks
            .find(kid)
            .ok_or_else(|| OidcError::JwkNotFound(kid.clone()))?;
        DecodingKey::from_jwk(jwk)?
    } else {
        let mut last_err: Option<jsonwebtoken::errors::Error> = None;
        for jwk in &jwks.keys {
            match DecodingKey::from_jwk(jwk) {
                Ok(key) => {
                    let val = build_validation(header.alg, issuer, audiences);
                    match decode::<serde_json::Value>(token, &key, &val) {
                        Ok(data) => {
                            check_nonce(&data, expected_nonce)?;
                            check_iat(&data)?;
                            return Ok(data.claims);
                        }
                        Err(e) => last_err = Some(e),
                    }
                }
                Err(e) => last_err = Some(e),
            }
        }
        return Err(last_err
            .map(OidcError::from)
            .unwrap_or(OidcError::NoJwksKeys));
    };

    let validation = build_validation(header.alg, issuer, audiences);
    let data: TokenData<serde_json::Value> = decode(token, &decoding_key, &validation)?;
    check_nonce(&data, expected_nonce)?;
    check_iat(&data)?;
    Ok(data.claims)
}

/// jsonwebtoken does not check `iat`, so reject one that is too far ahead.
fn check_iat(data: &TokenData<serde_json::Value>) -> Result<(), OidcError> {
    let iat = data.claims.get("iat").and_then(|v| v.as_u64()).unwrap_or(0);
    let now = chrono::Utc::now().timestamp() as u64;
    if iat > now + IAT_FUTURE_MAX_SECS {
        return Err(OidcError::IatInFuture { iat, now });
    }
    Ok(())
}

fn build_validation(alg: Algorithm, issuer: Option<&str>, audiences: &[&str]) -> Validation {
    let mut val = Validation::new(alg);
    val.validate_nbf = true;
    val.leeway = 60;
    val.required_spec_claims
        .extend(["sub", "aud"].map(String::from));
    if let Some(iss) = issuer {
        val.set_issuer(&[iss]);
    }
    if audiences.is_empty() {
        val.validate_aud = false;
    } else {
        val.set_audience(audiences);
    }
    val
}

fn check_nonce(
    data: &TokenData<serde_json::Value>,
    expected_nonce: Option<&str>,
) -> Result<(), OidcError> {
    if let Some(expected) = expected_nonce {
        let actual = data
            .claims
            .get("nonce")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if actual != expected {
            return Err(OidcError::NonceMismatch);
        }
    }
    Ok(())
}

/// Read `iss` from a JWT payload without verifying the token. Only use the
/// result to pick a trusted issuer; `verify_jwt` checks the signed claim later.
pub fn extract_issuer(token: &str) -> Result<String, OidcError> {
    decode_header(token)?;

    let mut segments = token.split('.');
    let payload = match (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) {
        (Some(_), Some(payload), Some(_), None) => payload,
        _ => {
            return Err(OidcError::MalformedToken(
                "expected exactly 3 dot-separated segments".to_string(),
            ));
        }
    };

    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|e| OidcError::MalformedToken(format!("payload is not base64url: {e}")))?;
    let claims: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|e| OidcError::MalformedToken(format!("payload is not JSON: {e}")))?;

    match claims.get("iss").and_then(|v| v.as_str()) {
        Some(iss) if !iss.is_empty() => Ok(iss.to_owned()),
        _ => Err(OidcError::MissingIssuer),
    }
}

/// Verify an external JWT (the `subject_token` of a token exchange) against the
/// JWKS of one of `trusted_issuers`. Returns the verified claims.
pub async fn verify_external_jwt(
    token: &str,
    trusted_issuers: &[&str],
    audiences: &[&str],
    client: &reqwest::Client,
) -> Result<serde_json::Value, OidcError> {
    let issuer = extract_issuer(token)?;

    // Check the allowlist before any network call.
    let claimed = issuer.trim_end_matches('/');
    let trusted = trusted_issuers
        .iter()
        .copied()
        .find(|t| t.trim_end_matches('/') == claimed)
        .ok_or_else(|| OidcError::UntrustedIssuer(issuer.clone()))?;

    let metadata = discover(trusted, client).await?;
    let jwks = fetch_jwks(&metadata.jwks_uri, client).await?;

    verify_jwt(token, &jwks, Some(&issuer), None, audiences)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::*;
    use chrono::{TimeDelta, Utc};
    use httpmock::prelude::*;
    use jsonwebtoken::{EncodingKey, Header as JwtHeader, encode};
    use serde_json::json;

    const ISS: &str = "https://iss.example.com";

    fn jwks() -> JwkSet {
        JwkSet {
            keys: vec![rsa_jwk(TEST_KID)],
        }
    }

    fn check(token: &str) -> Result<serde_json::Value, OidcError> {
        verify_jwt(token, &jwks(), Some(ISS), None, &["my-client"])
    }

    fn signed(claims: &serde_json::Value) -> String {
        make_jwt(claims, Some(TEST_KID))
    }

    // ── verify_jwt ───────────────────────────────────────────────────────────

    #[test]
    fn verify_jwt_accepts_valid_token() {
        let claims = check(&signed(&valid_claims(ISS, "my-client", None))).unwrap();
        assert_eq!(claims["sub"], "user123");
    }

    #[test]
    fn verify_jwt_rejects_wrong_issuer() {
        let token = signed(&valid_claims(
            "https://other.example.com",
            "my-client",
            None,
        ));
        assert!(matches!(check(&token), Err(OidcError::JwtDecode { .. })));
    }

    #[test]
    fn verify_jwt_rejects_expired_token() {
        let exp = (Utc::now() - TimeDelta::hours(1)).timestamp();
        let claims = json!({
            "sub": "u", "iss": ISS, "aud": "my-client", "exp": exp, "iat": exp - 3600,
        });
        assert!(matches!(
            check(&signed(&claims)),
            Err(OidcError::JwtDecode { .. })
        ));
    }

    #[test]
    fn verify_jwt_rejects_future_nbf() {
        let nbf = (Utc::now() + TimeDelta::hours(1)).timestamp();
        let claims = json!({
            "sub": "u", "iss": ISS, "aud": "my-client",
            "exp": nbf + 3600, "iat": Utc::now().timestamp(), "nbf": nbf,
        });
        assert!(matches!(
            check(&signed(&claims)),
            Err(OidcError::JwtDecode { .. })
        ));
    }

    #[test]
    fn verify_jwt_rejects_iat_too_far_in_future() {
        let iat = (Utc::now() + TimeDelta::hours(2)).timestamp();
        let claims = json!({
            "sub": "u", "iss": ISS, "aud": "my-client", "exp": iat + 3600, "iat": iat,
        });
        assert!(matches!(
            check(&signed(&claims)),
            Err(OidcError::IatInFuture { .. })
        ));
    }

    #[test]
    fn verify_jwt_rejects_missing_sub_and_aud() {
        let exp = (Utc::now() + TimeDelta::hours(1)).timestamp();
        let no_sub = json!({"iss": ISS, "aud": "my-client", "exp": exp});
        let no_aud = json!({"sub": "u", "iss": ISS, "exp": exp});
        assert!(check(&signed(&no_sub)).is_err());
        assert!(check(&signed(&no_aud)).is_err());
    }

    #[test]
    fn verify_jwt_checks_audience() {
        let other = signed(&valid_claims(ISS, "other-client", None));
        assert!(check(&other).is_err());

        let exp = (Utc::now() + TimeDelta::hours(1)).timestamp();
        let array = json!({
            "sub": "u", "iss": ISS, "aud": ["my-client", "other-client"],
            "exp": exp, "iat": Utc::now().timestamp(),
        });
        assert!(check(&signed(&array)).is_ok());
    }

    #[test]
    fn verify_jwt_checks_nonce() {
        let token = signed(&valid_claims(ISS, "my-client", Some("n1")));
        let ok = verify_jwt(&token, &jwks(), Some(ISS), Some("n1"), &["my-client"]);
        let bad = verify_jwt(&token, &jwks(), Some(ISS), Some("n2"), &["my-client"]);
        assert!(ok.is_ok());
        assert!(matches!(bad, Err(OidcError::NonceMismatch)));
    }

    #[test]
    fn verify_jwt_rejects_unknown_kid() {
        let token = make_jwt(&valid_claims(ISS, "my-client", None), Some("other"));
        assert!(matches!(check(&token), Err(OidcError::JwkNotFound(_))));
    }

    #[test]
    fn verify_jwt_without_kid_tries_all_keys() {
        let token = make_jwt(&valid_claims(ISS, "my-client", None), None);
        assert!(check(&token).is_ok());

        let empty: JwkSet = serde_json::from_value(json!({"keys": []})).unwrap();
        let result = verify_jwt(&token, &empty, None, None, &[]);
        assert!(matches!(result, Err(OidcError::NoJwksKeys)));
    }

    #[test]
    fn verify_jwt_picks_matching_key_from_several() {
        let jwks = JwkSet {
            keys: vec![rsa_jwk("old"), rsa_jwk(TEST_KID), rsa_jwk("unused")],
        };
        let token = signed(&valid_claims(ISS, "my-client", None));
        assert!(verify_jwt(&token, &jwks, Some(ISS), None, &["my-client"]).is_ok());
    }

    #[test]
    fn verify_jwt_rejects_hs256() {
        let key = EncodingKey::from_secret(b"secret");
        let token = encode(
            &JwtHeader::default(),
            &valid_claims(ISS, "my-client", None),
            &key,
        )
        .unwrap();
        assert!(matches!(
            check(&token),
            Err(OidcError::UnsupportedAlgorithm(_))
        ));
    }

    #[test]
    fn verify_jwt_rejects_alg_none() {
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\",\"typ\":\"JWT\"}");
        let payload = URL_SAFE_NO_PAD.encode(valid_claims(ISS, "my-client", None).to_string());
        assert!(matches!(
            check(&format!("{header}.{payload}.")),
            Err(OidcError::JwtDecode { .. })
        ));
    }

    #[test]
    fn verify_jwt_rejects_garbage() {
        assert!(matches!(
            check("not-a-jwt-at-all"),
            Err(OidcError::JwtDecode { .. })
        ));
    }

    #[test]
    fn verify_jwt_rejects_tampered_signature() {
        let token = signed(&valid_claims(ISS, "my-client", None));
        assert!(check(&token).is_ok());

        let (rest, sig) = token.rsplit_once('.').unwrap();
        let last = sig.chars().next_back().unwrap();
        let swap = if last == 'A' { 'B' } else { 'A' };
        let tampered = format!("{rest}.{}{swap}", &sig[..sig.len() - 1]);
        assert!(matches!(check(&tampered), Err(OidcError::JwtDecode { .. })));
    }

    #[test]
    fn verify_jwt_rejects_tampered_payload() {
        let token = signed(&valid_claims(ISS, "my-client", None));
        let mut parts = token.split('.');
        let header = parts.next().unwrap();
        let _payload = parts.next().unwrap();
        let signature = parts.next().unwrap();

        let mut evil = valid_claims(ISS, "my-client", None);
        evil["sub"] = json!("attacker");
        let evil_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&evil).unwrap());
        let tampered = format!("{header}.{evil_payload}.{signature}");
        assert!(matches!(check(&tampered), Err(OidcError::JwtDecode { .. })));
    }

    // ── extract_issuer / verify_external_jwt ─────────────────────────────────

    fn jwks_body() -> serde_json::Value {
        json!({"keys": [{
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": TEST_KID,
            "n": TEST_JWK_N, "e": TEST_JWK_E,
        }]})
    }

    fn mock_idp<'a>(
        server: &'a MockServer,
        issuer: &str,
        jwks: &serde_json::Value,
    ) -> (httpmock::Mock<'a>, httpmock::Mock<'a>) {
        let base_url = server.base_url();
        let discovery = server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(json!({
                "issuer": issuer,
                "authorization_endpoint": format!("{base_url}/auth"),
                "token_endpoint": format!("{base_url}/token"),
                "jwks_uri": format!("{base_url}/jwks"),
            }));
        });
        let jwks_mock = server.mock(|when, then| {
            when.method(GET).path("/jwks");
            then.status(200).json_body(jwks.clone());
        });
        (discovery, jwks_mock)
    }

    #[test]
    fn extract_issuer_returns_iss_claim() {
        let token = make_jwt(
            &valid_claims("https://iss.example.com", "my-client", None),
            Some(TEST_KID),
        );
        assert_eq!(extract_issuer(&token).unwrap(), "https://iss.example.com");
    }

    #[test]
    fn extract_issuer_does_not_verify_signature() {
        let token = make_jwt(
            &valid_claims("https://iss.example.com", "my-client", None),
            Some(TEST_KID),
        );
        let (rest, _sig) = token.rsplit_once('.').expect("token has a signature");
        let tampered = format!("{rest}.AAAA");
        assert_eq!(
            extract_issuer(&tampered).unwrap(),
            "https://iss.example.com"
        );
    }

    #[test]
    fn extract_issuer_rejects_missing_or_non_string_iss() {
        let exp = (Utc::now() + TimeDelta::hours(1)).timestamp();
        for claims in [
            json!({"sub": "u", "aud": "a", "exp": exp}),
            json!({"sub": "u", "aud": "a", "exp": exp, "iss": ""}),
            json!({"sub": "u", "aud": "a", "exp": exp, "iss": 42}),
            json!({"sub": "u", "aud": "a", "exp": exp, "iss": null}),
        ] {
            let token = make_jwt(&claims, Some(TEST_KID));
            assert!(
                matches!(extract_issuer(&token), Err(OidcError::MissingIssuer)),
                "{claims} must yield MissingIssuer"
            );
        }
    }

    #[test]
    fn extract_issuer_rejects_malformed_tokens() {
        assert!(matches!(
            extract_issuer("not-a-jwt-at-all"),
            Err(OidcError::JwtDecode { .. })
        ));

        let good = make_jwt(
            &valid_claims("https://iss.example.com", "my-client", None),
            Some(TEST_KID),
        );
        let mut parts = good.split('.');
        let header = parts.next().expect("header segment");
        let _payload = parts.next().expect("payload segment");
        let sig = parts.next().expect("signature segment");

        let bad_b64 = format!("{header}.!!!.{sig}");
        assert!(matches!(
            extract_issuer(&bad_b64),
            Err(OidcError::MalformedToken(_))
        ));

        let not_json = format!("{header}.{}.{sig}", URL_SAFE_NO_PAD.encode(b"not json"));
        assert!(matches!(
            extract_issuer(&not_json),
            Err(OidcError::MalformedToken(_))
        ));

        assert!(extract_issuer(&format!("{good}.extra")).is_err());
    }

    #[test]
    fn extract_issuer_rejects_alg_none() {
        let header = URL_SAFE_NO_PAD.encode(b"{\"alg\":\"none\",\"typ\":\"JWT\"}");
        let payload = URL_SAFE_NO_PAD.encode(json!({"iss": "https://iss.example.com"}).to_string());
        assert!(extract_issuer(&format!("{header}.{payload}.")).is_err());
    }

    #[tokio::test]
    async fn verify_external_jwt_accepts_valid_token() {
        let server = MockServer::start();
        let base_url = server.base_url();
        let (discovery, jwks) = mock_idp(&server, &base_url, &jwks_body());

        let token = make_jwt(&valid_claims(&base_url, "my-client", None), Some(TEST_KID));
        let claims = verify_external_jwt(
            &token,
            &[base_url.as_str()],
            &["my-client"],
            &reqwest::Client::new(),
        )
        .await
        .unwrap();

        assert_eq!(claims["sub"], "user123");
        assert_eq!(claims["iss"], base_url.as_str());
        discovery.assert_calls(1);
        jwks.assert_calls(1);
    }

    #[tokio::test]
    async fn verify_external_jwt_ignores_trailing_slash_on_trusted_issuer() {
        let server = MockServer::start();
        let base_url = server.base_url();
        mock_idp(&server, &base_url, &jwks_body());

        let token = make_jwt(&valid_claims(&base_url, "my-client", None), Some(TEST_KID));
        let trusted = format!("{base_url}/");
        verify_external_jwt(
            &token,
            &[trusted.as_str()],
            &["my-client"],
            &reqwest::Client::new(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn verify_external_jwt_rejects_untrusted_issuer_without_network_io() {
        let server = MockServer::start();
        let base_url = server.base_url();
        let (discovery, jwks) = mock_idp(&server, &base_url, &jwks_body());

        let token = make_jwt(
            &valid_claims("https://evil.example.com", "my-client", None),
            Some(TEST_KID),
        );
        let result = verify_external_jwt(
            &token,
            &[base_url.as_str()],
            &["my-client"],
            &reqwest::Client::new(),
        )
        .await;

        assert!(
            matches!(result, Err(OidcError::UntrustedIssuer(ref i)) if i == "https://evil.example.com"),
            "expected UntrustedIssuer, got {result:?}"
        );
        discovery.assert_calls(0);
        jwks.assert_calls(0);
    }

    #[tokio::test]
    async fn verify_external_jwt_rejects_empty_trusted_list() {
        let token = make_jwt(
            &valid_claims("https://iss.example.com", "my-client", None),
            Some(TEST_KID),
        );
        let result =
            verify_external_jwt(&token, &[], &["my-client"], &reqwest::Client::new()).await;
        assert!(matches!(result, Err(OidcError::UntrustedIssuer(_))));
    }

    #[tokio::test]
    async fn verify_external_jwt_rejects_tampered_payload() {
        let server = MockServer::start();
        let base_url = server.base_url();
        mock_idp(&server, &base_url, &jwks_body());

        let token = make_jwt(&valid_claims(&base_url, "my-client", None), Some(TEST_KID));
        let mut parts = token.split('.');
        let header = parts.next().expect("header segment");
        let _payload = parts.next().expect("payload segment");
        let signature = parts.next().expect("signature segment");

        let mut evil = valid_claims(&base_url, "my-client", None);
        evil["sub"] = json!("attacker");
        let evil_payload =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&evil).expect("claims serialize"));
        let tampered = format!("{header}.{evil_payload}.{signature}");

        let result = verify_external_jwt(
            &tampered,
            &[base_url.as_str()],
            &["my-client"],
            &reqwest::Client::new(),
        )
        .await;
        assert!(
            matches!(result, Err(OidcError::JwtDecode { .. })),
            "tampered payload must be rejected, got {result:?}"
        );
    }

    #[tokio::test]
    async fn verify_external_jwt_rejects_tampered_signature() {
        let server = MockServer::start();
        let base_url = server.base_url();
        mock_idp(&server, &base_url, &jwks_body());

        let token = make_jwt(&valid_claims(&base_url, "my-client", None), Some(TEST_KID));
        let (rest, sig) = token.rsplit_once('.').expect("token has a signature");
        let last = sig.chars().next_back().expect("signature is non-empty");
        let replacement = if last == 'A' { 'B' } else { 'A' };
        let tampered = format!("{rest}.{}{replacement}", &sig[..sig.len() - 1]);

        let result = verify_external_jwt(
            &tampered,
            &[base_url.as_str()],
            &["my-client"],
            &reqwest::Client::new(),
        )
        .await;
        assert!(
            matches!(result, Err(OidcError::JwtDecode { .. })),
            "tampered signature must be rejected, got {result:?}"
        );
    }

    #[tokio::test]
    async fn verify_external_jwt_rejects_signature_from_other_key_under_trusted_kid() {
        let mut other_n = TEST_JWK_N.to_string();
        let first = if other_n.starts_with('A') { "B" } else { "A" };
        other_n.replace_range(0..1, first);
        let other_jwks = json!({"keys": [{
            "kty": "RSA", "use": "sig", "alg": "RS256", "kid": TEST_KID,
            "n": other_n, "e": TEST_JWK_E,
        }]});

        let server = MockServer::start();
        let base_url = server.base_url();
        mock_idp(&server, &base_url, &other_jwks);

        let token = make_jwt(&valid_claims(&base_url, "my-client", None), Some(TEST_KID));
        let result = verify_external_jwt(
            &token,
            &[base_url.as_str()],
            &["my-client"],
            &reqwest::Client::new(),
        )
        .await;
        assert!(
            result.is_err(),
            "token must not verify against a different key, got {result:?}"
        );
    }

    #[tokio::test]
    async fn verify_external_jwt_rejects_unknown_kid() {
        let server = MockServer::start();
        let base_url = server.base_url();
        mock_idp(&server, &base_url, &jwks_body());

        let token = make_jwt(
            &valid_claims(&base_url, "my-client", None),
            Some("rotated-away-kid"),
        );
        let result = verify_external_jwt(
            &token,
            &[base_url.as_str()],
            &["my-client"],
            &reqwest::Client::new(),
        )
        .await;
        assert!(
            matches!(result, Err(OidcError::JwkNotFound(_))),
            "expected JwkNotFound, got {result:?}"
        );
    }

    #[tokio::test]
    async fn verify_external_jwt_rejects_discovery_issuer_mismatch() {
        let server = MockServer::start();
        let base_url = server.base_url();
        let (_discovery, jwks) = mock_idp(&server, "https://attacker.example.com", &jwks_body());

        let token = make_jwt(&valid_claims(&base_url, "my-client", None), Some(TEST_KID));
        let result = verify_external_jwt(
            &token,
            &[base_url.as_str()],
            &["my-client"],
            &reqwest::Client::new(),
        )
        .await;
        assert!(
            matches!(result, Err(OidcError::IssuerMismatch { .. })),
            "expected IssuerMismatch, got {result:?}"
        );
        jwks.assert_calls(0);
    }

    #[tokio::test]
    async fn verify_external_jwt_rejects_expired_token() {
        let server = MockServer::start();
        let base_url = server.base_url();
        mock_idp(&server, &base_url, &jwks_body());

        let exp = (Utc::now() - TimeDelta::hours(1)).timestamp();
        let claims = json!({
            "sub": "user", "iss": base_url, "aud": "my-client",
            "exp": exp, "iat": exp - 3600,
        });
        let token = make_jwt(&claims, Some(TEST_KID));
        let result = verify_external_jwt(
            &token,
            &[base_url.as_str()],
            &["my-client"],
            &reqwest::Client::new(),
        )
        .await;
        assert!(matches!(result, Err(OidcError::JwtDecode { .. })));
    }

    #[tokio::test]
    async fn verify_external_jwt_rejects_wrong_audience() {
        let server = MockServer::start();
        let base_url = server.base_url();
        mock_idp(&server, &base_url, &jwks_body());

        let token = make_jwt(
            &valid_claims(&base_url, "some-other-client", None),
            Some(TEST_KID),
        );
        let result = verify_external_jwt(
            &token,
            &[base_url.as_str()],
            &["my-client"],
            &reqwest::Client::new(),
        )
        .await;
        assert!(matches!(result, Err(OidcError::JwtDecode { .. })));
    }

    #[tokio::test]
    async fn verify_external_jwt_rejects_symmetric_algorithm() {
        let server = MockServer::start();
        let base_url = server.base_url();
        mock_idp(&server, &base_url, &jwks_body());

        let key = EncodingKey::from_secret(TEST_JWK_N.as_bytes());
        let claims = valid_claims(&base_url, "my-client", None);
        let token = encode(&JwtHeader::default(), &claims, &key).unwrap();

        let result = verify_external_jwt(
            &token,
            &[base_url.as_str()],
            &["my-client"],
            &reqwest::Client::new(),
        )
        .await;
        assert!(
            matches!(result, Err(OidcError::UnsupportedAlgorithm(_))),
            "expected UnsupportedAlgorithm, got {result:?}"
        );
    }

    #[tokio::test]
    async fn verify_external_jwt_propagates_jwks_fetch_failure() {
        let server = MockServer::start();
        let base_url = server.base_url();
        server.mock(|when, then| {
            when.method(GET).path("/.well-known/openid-configuration");
            then.status(200).json_body(json!({
                "issuer": base_url,
                "authorization_endpoint": format!("{base_url}/auth"),
                "token_endpoint": format!("{base_url}/token"),
                "jwks_uri": format!("{base_url}/jwks"),
            }));
        });
        server.mock(|when, then| {
            when.method(GET).path("/jwks");
            then.status(500);
        });

        let token = make_jwt(&valid_claims(&base_url, "my-client", None), Some(TEST_KID));
        let result = verify_external_jwt(
            &token,
            &[base_url.as_str()],
            &["my-client"],
            &reqwest::Client::new(),
        )
        .await;
        assert!(result.is_err(), "JWKS fetch failure must fail closed");
    }
}
