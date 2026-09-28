# Experiments

One script per claim. Each script should be runnable from the repository root,
print what it is measuring, and finish in a bounded amount of time.

Every script here must have a matching entry in
[`../docs/design-document.md`](../docs/design-document.md) stating what it
supports, how long it takes, and what output to expect.

## OAuth2 Token Exchange and Delegation
### JWT Generation
```
cd src/mock-jwt-generation

cargo run --bin server

cargo test --test token_integration -- --include-ignored --nocapture
```