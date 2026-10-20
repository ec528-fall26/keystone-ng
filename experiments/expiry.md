### Testing Exchanged Tokens Lifetimes are Capped #1353
1. ```cargo test -p openstack-keystone-core oauth2_client::token_exchange::tests``` Verifies expiry rules are in place
2. ```cargo test -p openstack-keystone api::v4::oauth2::token::token_exchange::tests``` Pings token endpoints
3. ```cargo check -p openstack-keystone --message-format=short``` Verifies everything complies together
4. ```cargo fmt --check``` Ensures proper code format as part of Keystone contributer documents