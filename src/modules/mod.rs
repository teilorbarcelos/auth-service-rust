pub mod auth;
pub mod observability;

use crate::{config::AppConfig, infra::cache::Cache};
use axum::Router;
use sea_orm::DatabaseConnection;

pub fn app_router(db: DatabaseConnection, cache: Cache, config: AppConfig) -> Router {
    Router::new().merge(auth::router(db.clone(), cache.clone(), config.clone()))
}
