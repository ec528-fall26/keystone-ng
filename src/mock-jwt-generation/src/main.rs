// src/main.rs

use mock_jwt_generation::{create_router, AppConfig};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    // Control verbosity with RUST_LOG:
    //   RUST_LOG=info  cargo run --bin server   <- request/response lines only
    //   RUST_LOG=debug cargo run --bin server   <- detailed validation logs (default)
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")),
        )
        .with_target(false) // hides module paths - cleaner for dev
        .with_thread_ids(false)
        .init();

    info!("Starting mock JWT development server");

    let public_key_pem = std::fs::read_to_string("keys/test-public.pem")
        .expect("Could not read keys/test-public.pem\n  Fix: bash keygen.sh");

    let trusted_issuer = "https://dev-test.okta.local/oauth2/default".to_string();
    let trusted_audience = "api://default".to_string();

    info!(
        issuer = %trusted_issuer,
        audience = %trusted_audience,
        algorithm = "RS256",
        public_key = "keys/test-public.pem",
        "Server configuration"
    );
    info!("Set RUST_LOG=info for request summaries or RUST_LOG=debug for validation details");

    let config = AppConfig {
        trusted_issuer,
        trusted_audience,
        public_key_pem,
    };

    let app = create_router(config);
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .expect("Failed to bind port 3000 - is something else using it?");

    info!(
        address = "http://localhost:3000",
        endpoint = "POST /token",
        "Listening"
    );

    axum::serve(listener, app).await.expect("Server crashed");
}
