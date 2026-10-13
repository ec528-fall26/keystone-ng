// src/lib.rs

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Json, Response},
    routing::post,
    Router,
};
use jsonwebtoken::{decode, errors::ErrorKind, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

// -- Server config -------------------------------------------------------------

pub struct AppConfig {
    pub trusted_issuer: String,
    pub trusted_audience: String,
    pub public_key_pem: String,
}

// -- Claim types ---------------------------------------------------------------

// exp and iat are added here purely for dev logging.
// jsonwebtoken validates them independently - having them in the
// struct just lets us print their values after a successful decode.
#[derive(Debug, Deserialize)]
struct VerifiedClaims {
    sub: String,
    jti: Option<String>,
    exp: Option<u64>,
    iat: Option<u64>,
}

#[derive(Serialize)]
struct TokenResponse {
    sub: String,
    scope: String,
}

// -- Handler -------------------------------------------------------------------

async fn token_handler(State(config): State<Arc<AppConfig>>, headers: HeaderMap) -> Response {
    info!(method = "POST", path = "/token", "Request received");

    // -- Step 1: Extract Bearer token ------------------------------------------
    let raw_token = match extract_bearer(&headers) {
        Some(t) => {
            debug!("Authorization header received");
            t
        }
        None => {
            warn!("Request rejected: missing or invalid authorization header");
            return reject("missing or invalid authorization header");
        }
    };

    // -- Step 2: Build decoding key --------------------------------------------
    let decoding_key = match DecodingKey::from_rsa_pem(config.public_key_pem.as_bytes()) {
        Ok(k) => {
            debug!("Configured RSA public key loaded");
            k
        }
        Err(e) => {
            error!(error = %e, "Could not load configured public key");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "server configuration error" })),
            )
                .into_response();
        }
    };

    // -- Step 3: Configure validation rules ------------------------------------

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[&config.trusted_audience]);
    validation.set_issuer(&[&config.trusted_issuer]);
    validation.validate_exp = true;

    // -- Step 4: Verify signature + decode claims ------------------------------
    let claims = match decode::<VerifiedClaims>(raw_token, &decoding_key, &validation) {
        Ok(data) => data.claims,
        Err(err) => {
            let (message, reason): (String, String) = match err.kind() {
                ErrorKind::ExpiredSignature => (
                    "token is expired".into(),
                    "expiration timestamp is in the past".into(),
                ),
                ErrorKind::InvalidAudience => (
                    "invalid audience".into(),
                    "audience does not match the configured value".into(),
                ),
                ErrorKind::InvalidIssuer => (
                    "invalid issuer".into(),
                    "issuer is not in the configured trusted list".into(),
                ),
                ErrorKind::InvalidSignature => (
                    "invalid signature".into(),
                    "signature verification failed".into(),
                ),
                ErrorKind::MissingRequiredClaim(c) => (
                    format!("{c} claim is required"),
                    format!("required claim '{c}' is absent from the token"),
                ),
                other => (
                    "invalid token".into(),
                    format!("unhandled validation error: {other:?}"),
                ),
            };
            warn!(reason = %reason, "Request rejected: {message}");
            return reject(message);
        }
    };

    debug!(
        subject = %claims.sub,
        jti = ?claims.jti,
        expires_at = ?claims.exp,
        issued_at = ?claims.iat,
        "Token signature and claims validated"
    );

    // -- Step 5: Business rule - jti must be present and non-empty -------------
    match &claims.jti {
        None => {
            warn!("Request rejected: jti claim is required");
            return reject("jti claim is required");
        }
        Some(jti) if jti.is_empty() => {
            warn!("Request rejected: jti claim must not be empty");
            return reject("jti claim must not be empty");
        }
        Some(jti) => {
            debug!(jti = %jti, "jti claim accepted");
        }
    }

    // -- All checks passed -----------------------------------------------------
    info!(status = 200, subject = %claims.sub, "Request accepted");

    (
        StatusCode::OK,
        Json(json!({
            "sub":   claims.sub,
            "scope": "read:api",
        })),
    )
        .into_response()
}

// -- Helpers -------------------------------------------------------------------

fn extract_bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("Authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

fn reject(message: impl Into<String>) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": message.into() })),
    )
        .into_response()
}

pub fn create_router(config: AppConfig) -> Router {
    Router::new()
        .route("/token", post(token_handler))
        .with_state(Arc::new(config))
}
