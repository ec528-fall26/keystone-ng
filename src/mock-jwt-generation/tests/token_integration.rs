// tests/token_integration.rs
//
// Remove #[ignore] from a test once the endpoint behaviour it covers is built.
// Run tests sequentially with output visible:
//   cargo test --test token_integration -- --include-ignored --nocapture --test-threads=1

mod common;

use common::{negative_vectors, MockJwtBuilder, TestReport};
use reqwest::Client;
use serde_json::Value;

// -- Helpers -------------------------------------------------------------------

fn base_url() -> String {
    std::env::var("API_BASE_URL").unwrap_or_else(|_| "http://localhost:3000".to_string())
}

/// Sends POST /token.  Passing `None` omits the Authorization header entirely,
/// which is its own negative test vector.
async fn post_token(client: &Client, token: Option<&str>) -> reqwest::Response {
    let url = format!("{}/token", base_url());
    println!("Request: POST {url}");

    let mut req = client.post(&url);
    if let Some(token) = token {
        println!("Authorization: Bearer <JWT>");
        req = req.header("Authorization", format!("Bearer {token}"));
    } else {
        println!("Authorization: <missing>");
    }

    req.send().await.unwrap_or_else(|e| {
        panic!(
            "HTTP request failed: {e}\n  \
             Is the server running?  cargo run --bin server\n  \
             Wrong port?             set API_BASE_URL=http://localhost:XXXX"
        )
    })
}

/// Consumes the response, prints status + body, and returns both for assertions.
async fn log_response(res: reqwest::Response) -> (u16, Value) {
    let status = res.status().as_u16();
    let status_text = res.status().canonical_reason().unwrap_or("Unknown");
    let body: Value = res
        .json()
        .await
        .unwrap_or_else(|_| serde_json::json!({ "error": "<non-JSON body>" }));

    println!("Response: {status} {status_text}");
    println!("Body:");
    println!(
        "{}",
        serde_json::to_string_pretty(&body)
            .unwrap_or_default()
            .lines()
            .map(|line| format!("  {line}"))
            .collect::<Vec<_>>()
            .join("\n")
    );

    (status, body)
}

async fn post_with_authorization(client: &Client, authorization: &str) -> reqwest::Response {
    let url = format!("{}/token", base_url());
    let scheme = authorization.split_whitespace().next().unwrap_or("<empty>");
    println!("Request: POST {url}");
    println!("Authorization scheme: {scheme}");
    client
        .post(&url)
        .header("Authorization", authorization)
        .send()
        .await
        .unwrap_or_else(|e| {
            panic!(
                "HTTP request failed: {e}\n  \
                 Is the server running?  cargo run --bin server\n  \
                 Wrong port?             set API_BASE_URL=http://localhost:XXXX"
            )
        })
}

// -- Happy path ----------------------------------------------------------------

#[tokio::test]
#[ignore = "activate when /token is reachable"]
async fn valid_token_returns_200() {
    let mut report = TestReport::start("valid_token_returns_200");

    let minted = MockJwtBuilder::new().mint();
    minted.describe("default happy-path token");

    let (status, _body) = log_response(post_token(&Client::new(), Some(&minted.token)).await).await;

    println!("  [assert] status == 200");
    assert_eq!(status, 200, "Expected 200 OK for a valid token");
    report.pass();
}

#[tokio::test]
#[ignore = "activate when /token is reachable"]
async fn valid_token_response_body_has_expected_shape() {
    let mut report = TestReport::start("valid_token_response_body_has_expected_shape");

    let minted = MockJwtBuilder::new().mint();
    minted.describe("default token");

    let (status, body) = log_response(post_token(&Client::new(), Some(&minted.token)).await).await;

    println!("  [assert] status == 200");
    assert_eq!(status, 200);

    println!("  [assert] body.sub == {:?}", minted.claims.sub);
    assert_eq!(body["sub"], minted.claims.sub);

    println!("  [assert] body.scope is a string");
    assert!(body["scope"].is_string(), "Expected scope to be a string");

    report.pass();
}

#[tokio::test]
#[ignore = "activate when /token is reachable"]
async fn valid_custom_subject_is_returned_in_response() {
    let mut report = TestReport::start("valid_custom_subject_is_returned_in_response");

    let minted = MockJwtBuilder::new()
        .subject("custom-user@example.com")
        .mint();
    minted.describe("token with custom subject");

    let (status, body) = log_response(post_token(&Client::new(), Some(&minted.token)).await).await;

    assert_eq!(status, 200);
    assert_eq!(body["sub"], "custom-user@example.com");
    report.pass();
}

#[tokio::test]
#[ignore = "activate when /token is reachable"]
async fn token_with_multiple_audiences_returns_200() {
    let mut report = TestReport::start("token_with_multiple_audiences_returns_200");

    let minted = MockJwtBuilder::new()
        .audiences(vec!["api://default", "api://mobile"])
        .mint();
    minted.describe("multi-audience token");

    let (status, _body) = log_response(post_token(&Client::new(), Some(&minted.token)).await).await;

    println!("  [assert] status == 200");
    assert_eq!(status, 200);
    report.pass();
}

// -- Rejection cases -----------------------------------------------------------

#[tokio::test]
#[ignore = "activate when /token is reachable"]
async fn no_authorization_header_returns_401() {
    let mut report = TestReport::start("no_authorization_header_returns_401");
    println!("  Sending request with no Authorization header at all");

    let (status, body) = log_response(post_token(&Client::new(), None).await).await;

    println!("  [assert] status == 401");
    assert_eq!(status, 401);

    println!("  [assert] body.error is present");
    assert!(
        body.get("error").is_some(),
        "Response must include an error field"
    );
    report.pass();
}

#[tokio::test]
#[ignore = "activate when /token is reachable"]
async fn malformed_token_returns_401() {
    let mut report = TestReport::start("malformed_token_returns_401");

    let (status, body) = log_response(post_token(&Client::new(), Some("not-a-jwt")).await).await;

    assert_eq!(status, 401);
    assert!(
        body["error"].is_string(),
        "Response should describe the rejection"
    );
    report.pass();
}

#[tokio::test]
#[ignore = "activate when /token is reachable"]
async fn unsupported_authorization_scheme_returns_401() {
    let mut report = TestReport::start("unsupported_authorization_scheme_returns_401");

    let minted = MockJwtBuilder::new().mint();
    let authorization = format!("Basic {}", minted.token);
    let (status, body) =
        log_response(post_with_authorization(&Client::new(), &authorization).await).await;

    assert_eq!(status, 401);
    assert_eq!(body["error"], "missing or invalid authorization header");
    report.pass();
}

#[tokio::test]
#[ignore = "activate when /token is reachable"]
async fn expired_token_returns_401() {
    let mut report = TestReport::start("expired_token_returns_401");

    let minted = negative_vectors::expired();
    minted.describe("expired token (negative vector)");

    let (status, body) = log_response(post_token(&Client::new(), Some(&minted.token)).await).await;

    println!("  [assert] status == 401");
    assert_eq!(status, 401);

    let error = body["error"].as_str().unwrap_or("");
    println!("  [assert] error contains 'expired' - got: {error:?}");
    assert!(
        error.to_ascii_lowercase().contains("expired"),
        "Error message should mention expiry"
    );
    report.pass();
}

#[tokio::test]
#[ignore = "activate when /token is reachable"]
async fn wrong_audience_returns_401() {
    let mut report = TestReport::start("wrong_audience_returns_401");

    let minted = negative_vectors::wrong_audience();
    minted.describe("wrong-audience token (negative vector)");

    let (status, body) = log_response(post_token(&Client::new(), Some(&minted.token)).await).await;

    println!("  [assert] status == 401");
    assert_eq!(status, 401);
    println!("Rejection reason: {}", body["error"]);
    report.pass();
}

#[tokio::test]
#[ignore = "activate when /token is reachable"]
async fn wrong_issuer_returns_401() {
    let mut report = TestReport::start("wrong_issuer_returns_401");

    let minted = negative_vectors::wrong_issuer();
    minted.describe("wrong-issuer token (negative vector)");

    let (status, body) = log_response(post_token(&Client::new(), Some(&minted.token)).await).await;

    println!("  [assert] status == 401");
    assert_eq!(status, 401);
    println!("Rejection reason: {}", body["error"]);
    report.pass();
}

#[tokio::test]
#[ignore = "activate when /token is reachable"]
async fn tampered_signature_returns_401() {
    let mut report = TestReport::start("tampered_signature_returns_401");
    println!("  Token is well-formed but signed with an untrusted rogue key.");
    println!("  Rejection must come from signature verification, not claims.");

    let minted = negative_vectors::invalid_signature();
    minted.describe("rogue-signed token (negative vector)");

    let (status, body) = log_response(post_token(&Client::new(), Some(&minted.token)).await).await;

    println!("  [assert] status == 401");
    assert_eq!(status, 401);
    println!("Rejection reason: {}", body["error"]);
    report.pass();
}

#[tokio::test]
#[ignore = "activate when /token is reachable"]
async fn empty_jti_returns_401() {
    let mut report = TestReport::start("empty_jti_returns_401");
    println!("  All claims valid except jti is an empty string.");
    println!("  Tests the post-decode business rule in the handler.");

    let minted = negative_vectors::empty_jti();
    minted.describe("empty-jti token (negative vector)");

    let (status, body) = log_response(post_token(&Client::new(), Some(&minted.token)).await).await;

    println!("  [assert] status == 401");
    assert_eq!(status, 401);
    println!("Rejection reason: {}", body["error"]);
    report.pass();
}

#[tokio::test]
#[ignore = "activate when /token is reachable"]
async fn missing_expiry_claim_returns_401() {
    let mut report = TestReport::start("missing_expiry_claim_returns_401");
    println!("  Token has no exp claim at all.");
    println!("  Validates that the server enforces exp presence.");

    let minted = negative_vectors::no_expiry();
    minted.describe("no-expiry token (negative vector)");

    let (status, body) = log_response(post_token(&Client::new(), Some(&minted.token)).await).await;

    println!("  [assert] status == 401");
    assert_eq!(status, 401);
    println!("Rejection reason: {}", body["error"]);
    report.pass();
}
