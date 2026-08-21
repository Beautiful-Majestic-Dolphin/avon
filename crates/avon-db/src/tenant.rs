use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::pool::DbError;

/// The tenant created by the initial migration.
pub const DEFAULT_TENANT_ID: Uuid = Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0001);

/// Begin a transaction with `avon.tenant_id` set for row-level security.
/// The setting is `SET LOCAL`, so it ends with the transaction.
pub async fn begin_tenant(
    pool: &PgPool,
    tenant: Uuid,
) -> Result<Transaction<'static, Postgres>, DbError> {
    let mut tx = pool.begin().await.map_err(DbError::Query)?;
    sqlx::query("SELECT set_config('avon.tenant_id', $1, true)")
        .bind(tenant.to_string())
        .execute(&mut *tx)
        .await
        .map_err(DbError::Query)?;
    Ok(tx)
}
