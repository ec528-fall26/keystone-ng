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

use std::sync::Arc;

use eyre::Result;
use tracing_test::traced_test;
use uuid::Uuid;

use openstack_keystone_api_types::v3::credential::*;
use openstack_sdk::{AsyncOpenStack, config::CloudConfig};

use test_api::asserts::assert_forbidden;
use test_api::credential::{create_credential, list_credentials};
use test_api::fixtures::{
    ProjectScopedUser, cleanup_project_scoped_users, warn_on_cleanup_failure,
};
use test_api::guard::ResourceGuard;

async fn admin_session() -> Result<Arc<AsyncOpenStack>> {
    Ok(Arc::new(
        AsyncOpenStack::new(&CloudConfig::from_env()?).await?,
    ))
}

/// Two independent `member` users; `a` will attempt to list `b`'s
/// credentials.
async fn two_members(
    admin: &Arc<AsyncOpenStack>,
) -> Result<(ProjectScopedUser, ProjectScopedUser)> {
    let a = ProjectScopedUser::provision(admin, "default", "member").await?;
    match ProjectScopedUser::provision(admin, "default", "member").await {
        Ok(b) => Ok((a, b)),
        Err(error) => {
            warn_on_cleanup_failure("member fixture", a.cleanup().await);
            Err(error)
        }
    }
}

#[tokio::test]
#[traced_test]
async fn test_list_includes_created_credential() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let blob = format!(r#"{{"seed":"{}"}}"#, Uuid::new_v4().simple());

    let guard = create_credential(
        &tc,
        CredentialCreateBuilder::default()
            .blob(blob)
            .r#type("totp")
            .build()?,
    )
    .await?;

    let all = list_credentials(&tc, None, None).await?;
    assert!(
        all.iter().any(|c| c.id == guard.id),
        "created credential must appear in the unfiltered list"
    );

    guard.delete().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_list_filtered_by_type_excludes_other_types() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let blob = format!(r#"{{"seed":"{}"}}"#, Uuid::new_v4().simple());
    let marker_type = format!("custom-{}", Uuid::new_v4().simple());

    let guard = create_credential(
        &tc,
        CredentialCreateBuilder::default()
            .blob(blob)
            .r#type(marker_type.clone())
            .build()?,
    )
    .await?;

    let filtered = list_credentials(&tc, Some(&marker_type), None).await?;
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].id, guard.id);

    let other = list_credentials(&tc, Some("totp"), None).await?;
    assert!(!other.iter().any(|c| c.id == guard.id));

    guard.delete().await?;
    Ok(())
}

#[tokio::test]
#[traced_test]
async fn test_list_filtered_by_user_id() -> Result<()> {
    let tc = Arc::new(AsyncOpenStack::new(&CloudConfig::from_env()?).await?);
    let blob = format!(r#"{{"seed":"{}"}}"#, Uuid::new_v4().simple());

    let guard = create_credential(
        &tc,
        CredentialCreateBuilder::default()
            .blob(blob)
            .r#type("totp")
            .build()?,
    )
    .await?;

    let filtered = list_credentials(&tc, None, Some(&guard.user_id)).await?;
    assert!(filtered.iter().all(|c| c.user_id == guard.user_id));
    assert!(filtered.iter().any(|c| c.id == guard.id));

    guard.delete().await?;
    Ok(())
}

// --- issue #1117: an ordinary member may list only their own credentials ---
//
// The suite's ambient session is the bootstrap **admin**, which takes the
// privileged branch of `identity/credential/list` and so cannot observe the
// restriction at all; these cases act through a genuinely unprivileged
// project-scoped `member` session instead.

/// The happy path the restriction has to preserve: a `member` filtering to
/// their own `user_id` still gets their own credentials back.
#[tokio::test]
#[traced_test]
async fn test_list_own_user_id_allowed_for_member() -> Result<()> {
    let admin = admin_session().await?;
    let member = ProjectScopedUser::provision(&admin, "default", "member").await?;
    let blob = format!(r#"{{"seed":"{}"}}"#, Uuid::new_v4().simple());

    let guard = create_credential(
        &member.session,
        CredentialCreateBuilder::default()
            .blob(blob)
            .r#type("totp")
            .build()?,
    )
    .await?;

    let own = list_credentials(&member.session, None, Some(&member.user.id)).await?;
    assert!(
        own.iter().any(|c| c.id == guard.id),
        "member filtering to their own user_id must see their own credential"
    );
    assert!(
        own.iter().all(|c| c.user_id == member.user.id),
        "the filter must be applied by the driver, not merely approved by policy"
    );

    guard.delete().await?;
    member.cleanup().await?;
    Ok(())
}

/// The bug itself (issue #1117): an unfiltered list let any `member` walk
/// the whole credential table. The per-item `identity/credential/show`
/// re-check meant nothing leaked, but the scan still happened — one cheap
/// request per full-table scan plus an OPA round-trip per row.
#[tokio::test]
#[traced_test]
async fn test_list_unfiltered_forbidden_for_member() -> Result<()> {
    let admin = admin_session().await?;
    let member = ProjectScopedUser::provision(&admin, "default", "member").await?;

    assert_forbidden(
        list_credentials(&member.session, None, None).await,
        "member must not be able to list the whole credential collection",
    );

    // A `type` filter is not a way around the missing ownership filter.
    assert_forbidden(
        list_credentials(&member.session, Some("totp"), None).await,
        "a type filter must not substitute for the user_id filter",
    );

    member.cleanup().await?;
    Ok(())
}

/// Filtering to somebody else's `user_id` must not buy the scan either,
/// otherwise the filter would be a formality rather than a boundary.
#[tokio::test]
#[traced_test]
async fn test_list_other_user_id_forbidden_for_member() -> Result<()> {
    let admin = admin_session().await?;
    let (a, b) = two_members(&admin).await?;

    assert_forbidden(
        list_credentials(&a.session, None, Some(&b.user.id)).await,
        "member must not be able to list another user's credentials",
    );

    cleanup_project_scoped_users([a, b]).await?;
    Ok(())
}
