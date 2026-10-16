// tests/common/mod.rs

use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// -- Defaults ------------------------------------------------------------------

pub const DEFAULT_ISSUER: &str = "https://dev-test.okta.local/oauth2/default";
pub const DEFAULT_AUDIENCE: &str = "api://default";
pub const DEFAULT_SUBJECT: &str = "test-user@example.com";
pub const DEFAULT_EXPIRY_SECS: u64 = 3_600;

// -- Key loading ---------------------------------------------------------------

static TEST_PRIVATE_KEY: OnceLock<String> = OnceLock::new();
static TEST_PUBLIC_KEY: OnceLock<String> = OnceLock::new();
static ROGUE_PRIVATE_KEY: OnceLock<String> = OnceLock::new();

pub fn test_private_key() -> &'static str {
    TEST_PRIVATE_KEY.get_or_init(|| {
        load_pem(
            "TEST_PRIVATE_KEY_PATH",
            "keys/test-private.pem",
            "test private",
        )
    })
}

pub fn test_public_key() -> &'static str {
    TEST_PUBLIC_KEY.get_or_init(|| {
        load_pem(
            "TEST_PUBLIC_KEY_PATH",
            "keys/test-public.pem",
            "test public",
        )
    })
}

fn rogue_private_key() -> &'static str {
    ROGUE_PRIVATE_KEY.get_or_init(|| {
        load_pem(
            "TEST_ROGUE_KEY_PATH",
            "keys/rogue-private.pem",
            "rogue private",
        )
    })
}

fn load_pem(env_var: &str, default_path: &str, label: &str) -> String {
    let path = std::env::var(env_var).unwrap_or_else(|_| default_path.to_string());
    std::fs::read_to_string(&path).unwrap_or_else(|err| {
        panic!(
            "\nFailed to load {label} key.\n  \
             Path : {path}\n  \
             Error: {err}\n  \
             Fix  : bash keygen.sh\n  \
             Alt  : set {env_var} env var to an alternate path.\n"
        )
    })
}

// -- Payload types -------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AudienceClaim {
    Single(String),
    Multiple(Vec<String>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: AudienceClaim,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    pub iat: u64,
    pub jti: String,
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// -- Minted token --------------------------------------------------------------

pub struct MintedToken {
    pub token: String,
    pub claims: Claims,
    pub public_key_pem: String,
}

pub struct TestReport {
    passed: bool,
}

impl TestReport {
    pub fn start(test_name: &str) -> Self {
        let title = test_name.replace('_', " ");
        println!("\n{}", "=".repeat(72));
        println!("TEST: {title}");
        println!("{}", "-".repeat(72));
        Self { passed: false }
    }

    pub fn pass(&mut self) {
        self.passed = true;
    }
}

impl Drop for TestReport {
    fn drop(&mut self) {
        println!("RESULT: {}", if self.passed { "PASS" } else { "FAIL" });
        println!("{}", "=".repeat(72));
    }
}

impl MintedToken {
    pub fn as_bearer(&self) -> String {
        format!("Bearer {}", self.token)
    }

    /// Prints a formatted claim-by-claim summary of this token.
    ///
    /// Call this inside a test before sending the request to see exactly
    /// what is being submitted. Requires `-- --nocapture` to display.
    ///
    /// ```
    /// let minted = MockJwtBuilder::new().mint();
    /// minted.describe("default happy-path token");
    /// ```
    pub fn describe(&self, label: &str) {
        let now = now_secs();

        println!("JWT claims ({label}):");
        println!("  Issuer: {}", self.claims.iss);

        match &self.claims.aud {
            AudienceClaim::Single(a) => println!("  Audience: {a}"),
            AudienceClaim::Multiple(av) => println!("  Audience: {:?}", av),
        }

        println!("  Subject: {}", self.claims.sub);

        match self.claims.exp {
            Some(exp) if exp > now => {
                println!("  Expires: {exp} (valid for {}s)", exp - now)
            }
            Some(exp) => {
                println!("  Expires: {exp} (expired {}s ago)", now - exp)
            }
            None => println!("  Expires: <missing>"),
        }

        println!("  Issued at: {}", self.claims.iat);

        if self.claims.jti.is_empty() {
            println!("  JWT ID: <empty>");
        } else {
            println!("  JWT ID: {}", self.claims.jti);
        }

        if !self.claims.extra.is_empty() {
            println!("  Additional claims:");
            for (k, v) in &self.claims.extra {
                println!("    {k}: {v}");
            }
        }
        println!("  JWT: <omitted>");
    }
}

// -- Builder -------------------------------------------------------------------

pub struct MockJwtBuilder {
    aud: Option<AudienceClaim>,
    iss: Option<String>,
    exp: Option<u64>,
    omit_exp: bool,
    jti: Option<String>,
    sub: Option<String>,
    extra_claims: Map<String, Value>,
    signing_key_pem: Option<String>,
    algorithm: Algorithm,
}

impl Default for MockJwtBuilder {
    fn default() -> Self {
        Self {
            aud: None,
            iss: None,
            exp: None,
            omit_exp: false,
            jti: None,
            sub: None,
            extra_claims: Map::new(),
            signing_key_pem: None,
            algorithm: Algorithm::RS256,
        }
    }
}

impl MockJwtBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn audience(mut self, aud: impl Into<String>) -> Self {
        self.aud = Some(AudienceClaim::Single(aud.into()));
        self
    }

    pub fn audiences(mut self, aud: Vec<impl Into<String>>) -> Self {
        self.aud = Some(AudienceClaim::Multiple(
            aud.into_iter().map(Into::into).collect(),
        ));
        self
    }

    pub fn issuer(mut self, iss: impl Into<String>) -> Self {
        self.iss = Some(iss.into());
        self
    }

    pub fn expires_at(mut self, unix_secs: u64) -> Self {
        self.exp = Some(unix_secs);
        self
    }

    pub fn already_expired(self) -> Self {
        self.expires_at(now_secs().saturating_sub(3_600))
    }

    pub fn without_expiry(mut self) -> Self {
        self.omit_exp = true;
        self
    }

    pub fn jti(mut self, jti: impl Into<String>) -> Self {
        self.jti = Some(jti.into());
        self
    }

    pub fn subject(mut self, sub: impl Into<String>) -> Self {
        self.sub = Some(sub.into());
        self
    }

    pub fn claim(mut self, key: impl Into<String>, value: Value) -> Self {
        self.extra_claims.insert(key.into(), value);
        self
    }

    pub fn signing_key(mut self, pem: impl Into<String>) -> Self {
        self.signing_key_pem = Some(pem.into());
        self
    }

    pub fn mint(self) -> MintedToken {
        let now = now_secs();

        let claims = Claims {
            iss: self.iss.unwrap_or_else(|| DEFAULT_ISSUER.to_string()),
            sub: self.sub.unwrap_or_else(|| DEFAULT_SUBJECT.to_string()),
            aud: self
                .aud
                .unwrap_or_else(|| AudienceClaim::Single(DEFAULT_AUDIENCE.to_string())),
            exp: if self.omit_exp {
                None
            } else {
                Some(self.exp.unwrap_or(now + DEFAULT_EXPIRY_SECS))
            },
            iat: now,
            jti: self.jti.unwrap_or_else(|| Uuid::new_v4().to_string()),
            extra: self.extra_claims,
        };

        let key_pem = self
            .signing_key_pem
            .as_deref()
            .unwrap_or_else(|| test_private_key());

        let enc_key = EncodingKey::from_rsa_pem(key_pem.as_bytes()).unwrap_or_else(|e| {
            panic!(
                "\nFailed to build EncodingKey: {e}\n  \
                 Expected PKCS#8 PEM format.\n  \
                 Re-run: bash keygen.sh\n"
            )
        });

        let token = encode(&Header::new(self.algorithm), &claims, &enc_key)
            .expect("JWT signing failed - bug in test factory");

        MintedToken {
            token,
            claims,
            public_key_pem: test_public_key().to_owned(),
        }
    }
}

// -- Negative vectors ----------------------------------------------------------

pub mod negative_vectors {
    use super::*;

    pub fn expired() -> MintedToken {
        MockJwtBuilder::new().already_expired().mint()
    }

    pub fn wrong_audience() -> MintedToken {
        MockJwtBuilder::new()
            .audience("https://rogue-client.example.com")
            .mint()
    }

    pub fn wrong_issuer() -> MintedToken {
        MockJwtBuilder::new()
            .issuer("https://attacker.evil.example")
            .mint()
    }

    pub fn invalid_signature() -> MintedToken {
        MockJwtBuilder::new()
            .signing_key(rogue_private_key())
            .mint()
    }

    pub fn empty_jti() -> MintedToken {
        MockJwtBuilder::new().jti("").mint()
    }

    pub fn no_expiry() -> MintedToken {
        MockJwtBuilder::new().without_expiry().mint()
    }
}

// -- Internal helpers ----------------------------------------------------------

pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("System clock is before the Unix epoch")
        .as_secs()
}

// -- Factory self-tests --------------------------------------------------------

#[cfg(test)]
mod factory_tests {
    use super::*;
    use jsonwebtoken::{decode, errors::ErrorKind, DecodingKey, Validation};
    use serde_json::json;

    fn verify(minted: &MintedToken) -> Result<Claims, jsonwebtoken::errors::Error> {
        let key = DecodingKey::from_rsa_pem(minted.public_key_pem.as_bytes())
            .expect("Failed to build DecodingKey");
        let mut val = Validation::new(Algorithm::RS256);
        val.set_audience(&[DEFAULT_AUDIENCE]);
        val.set_issuer(&[DEFAULT_ISSUER]);
        decode::<Claims>(&minted.token, &key, &val).map(|td| td.claims)
    }

    #[test]
    fn default_token_passes_full_verification() {
        let mut report = TestReport::start("default_token_passes_full_verification");
        let minted = MockJwtBuilder::new().mint();
        minted.describe("default token");

        println!("  Verifying against trusted public key...");
        let claims = verify(&minted).expect("Default token should verify");

        println!("  iss match : {}", claims.iss);
        assert_eq!(claims.iss, DEFAULT_ISSUER);

        println!("  aud match : {:?}", claims.aud);
        assert_eq!(
            claims.aud,
            AudienceClaim::Single(DEFAULT_AUDIENCE.to_string())
        );

        let exp = claims.exp.unwrap();
        println!("  exp valid : {exp} > {}", now_secs());
        assert!(exp > now_secs());
        report.pass();
    }

    #[test]
    fn claim_overrides_are_encoded_in_a_test_key_signed_jwt() {
        let mut report = TestReport::start("claim_overrides_are_encoded_in_a_test_key_signed_jwt");
        let exp = now_secs() + 600;
        let minted = MockJwtBuilder::new()
            .audience("api://custom")
            .issuer("https://issuer.example.test")
            .expires_at(exp)
            .jti("custom-jti")
            .mint();

        assert_eq!(minted.token.split('.').count(), 3);
        assert_eq!(
            jsonwebtoken::decode_header(&minted.token)
                .expect("JWT header should decode")
                .alg,
            Algorithm::RS256
        );

        let key = DecodingKey::from_rsa_pem(test_public_key().as_bytes())
            .expect("Failed to build test DecodingKey");
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&["api://custom"]);
        validation.set_issuer(&["https://issuer.example.test"]);

        let claims = decode::<Claims>(&minted.token, &key, &validation)
            .expect("Token should verify with the known local test key")
            .claims;
        assert_eq!(
            claims.aud,
            AudienceClaim::Single("api://custom".to_string())
        );
        assert_eq!(claims.iss, "https://issuer.example.test");
        assert_eq!(claims.exp, Some(exp));
        assert_eq!(claims.jti, "custom-jti");
        report.pass();
    }

    #[test]
    fn extra_claims_appear_as_top_level_fields() {
        let mut report = TestReport::start("extra_claims_appear_as_top_level_fields");
        let minted = MockJwtBuilder::new()
            .claim("scp", json!("read:api write:api"))
            .claim("groups", json!(["admins", "developers"]))
            .mint();
        minted.describe("token with extra claims");

        println!("  scp    : {:?}", minted.claims.extra["scp"]);
        println!("  groups : {:?}", minted.claims.extra["groups"]);

        assert_eq!(minted.claims.extra["scp"], json!("read:api write:api"));
        assert_eq!(
            minted.claims.extra["groups"],
            json!(["admins", "developers"])
        );
        println!("  Both extra claims are present as top-level fields");
        report.pass();
    }

    #[test]
    fn multi_audience_serialises_as_array() {
        let mut report = TestReport::start("multi_audience_serialises_as_array");
        let minted = MockJwtBuilder::new()
            .audiences(vec!["api://default", "api://mobile"])
            .mint();
        minted.describe("multi-audience token");

        assert_eq!(
            minted.claims.aud,
            AudienceClaim::Multiple(vec![
                "api://default".to_string(),
                "api://mobile".to_string(),
            ])
        );
        println!("  aud is serialized as a JSON array");
        report.pass();
    }

    #[test]
    fn expired_token_has_past_exp() {
        let mut report = TestReport::start("expired_token_has_past_exp");
        let minted = negative_vectors::expired();
        minted.describe("expired token (negative vector)");

        let exp = minted.claims.exp.unwrap();
        println!("  exp {} < now {}", exp, now_secs());
        assert!(exp < now_secs());
        report.pass();
    }

    #[test]
    fn no_expiry_token_omits_exp_field() {
        let mut report = TestReport::start("no_expiry_token_omits_exp_field");
        let minted = negative_vectors::no_expiry();
        minted.describe("no-expiry token (negative vector)");

        println!("  exp field : {:?}", minted.claims.exp);
        assert!(minted.claims.exp.is_none(), "exp should be absent");
        println!("  exp is absent from the payload");
        report.pass();
    }

    #[test]
    fn invalid_signature_token_fails_verification() {
        let mut report = TestReport::start("invalid_signature_token_fails_verification");
        let minted = negative_vectors::invalid_signature();
        minted.describe("rogue-signed token (negative vector)");

        println!("  Attempting verification against TRUSTED public key...");
        let result = verify(&minted);
        println!(
            "  Result : {:?}",
            result.as_ref().map(|_| "Ok").unwrap_or("Err")
        );
        assert!(
            result.is_err(),
            "Must fail - signed with untrusted rogue key"
        );
        println!("  Rejected as expected");
        report.pass();
    }

    #[test]
    fn signed_negative_claim_vectors_fail_the_expected_validation() {
        let mut report =
            TestReport::start("signed_negative_claim_vectors_fail_the_expected_validation");
        let expired = negative_vectors::expired();
        assert!(matches!(
            verify(&expired).unwrap_err().kind(),
            ErrorKind::ExpiredSignature
        ));

        let wrong_audience = negative_vectors::wrong_audience();
        assert!(matches!(
            verify(&wrong_audience).unwrap_err().kind(),
            ErrorKind::InvalidAudience
        ));

        let wrong_issuer = negative_vectors::wrong_issuer();
        assert!(matches!(
            verify(&wrong_issuer).unwrap_err().kind(),
            ErrorKind::InvalidIssuer
        ));
        report.pass();
    }

    #[test]
    fn empty_jti_vector_remains_signed_and_has_an_empty_claim() {
        let mut report =
            TestReport::start("empty_jti_vector_remains_signed_and_has_an_empty_claim");
        let minted = negative_vectors::empty_jti();
        let claims = verify(&minted).expect("Empty jti should not invalidate JWT signature");

        assert!(claims.jti.is_empty());
        report.pass();
    }

    #[test]
    fn each_default_token_has_unique_jti() {
        let mut report = TestReport::start("each_default_token_has_unique_jti");
        let a = MockJwtBuilder::new().mint();
        let b = MockJwtBuilder::new().mint();

        println!("  jti A : {}", a.claims.jti);
        println!("  jti B : {}", b.claims.jti);
        assert_ne!(a.claims.jti, b.claims.jti);
        println!("  Each call produces a unique jti");
        report.pass();
    }
}
