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
//! # Create Endpoint

use sea_orm::DatabaseConnection;
use sea_orm::entity::*;

use openstack_keystone_core::catalog::CatalogProviderError;
use openstack_keystone_core::error::DbContextExt;
use openstack_keystone_core_types::catalog::{Endpoint, EndpointCreate};

use crate::entity::endpoint as db_endpoint;

/// Creates a new endpoint.
///
/// # Parameters
/// - `db`: The database connection.
/// - `endpoint`: The endpoint creation parameters.
///
/// # Returns
/// A `Result` containing the created `Endpoint`, or an `Error`.
pub async fn create(
    db: &DatabaseConnection,
    endpoint: EndpointCreate,
) -> Result<Endpoint, CatalogProviderError> {
    TryInto::<db_endpoint::ActiveModel>::try_into(endpoint)?
        .insert(db)
        .await
        .context("creating endpoint")?
        .try_into()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::*;

    #[tokio::test]
    async fn test_create() {
        let db = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![db_endpoint::Model {
                id: "ep-1".into(),
                legacy_endpoint_id: None,
                interface: "public".into(),
                service_id: "svc-1".into(),
                url: "http://localhost".into(),
                extra: None,
                enabled: true,
                region_id: Some("region-1".into()),
            }]])
            .into_connection();

        let endpoint_create = EndpointCreate {
            enabled: true,
            extra: HashMap::new(),
            id: Some("ep-1".to_string()),
            interface: "public".to_string(),
            region_id: Some("region-1".to_string()),
            service_id: "svc-1".to_string(),
            url: "http://localhost".to_string(),
        };

        let created = create(&db, endpoint_create).await.unwrap();

        assert_eq!(created.id, "ep-1");
        assert_eq!(created.interface, "public");
        assert_eq!(created.service_id, "svc-1");
        assert_eq!(created.url, "http://localhost");
        assert_eq!(created.region_id.as_deref(), Some("region-1"));
        assert!(created.enabled);
    }
}
