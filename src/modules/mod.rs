pub mod audit;
pub mod audit_explorer;
pub mod auth;
pub mod dashboard;
pub mod observability;
pub mod product;
pub mod role;
pub mod upload;
pub mod user;

use crate::{config::AppConfig, infra::cache::Cache};
use axum::Router;
use sea_orm::DatabaseConnection;

pub fn app_router(db: DatabaseConnection, cache: Cache, config: AppConfig) -> Router {
    Router::new()
        .merge(auth::router(db.clone(), cache.clone(), config.clone()))
        .merge(user::router(db.clone(), cache.clone(), config.clone()))
        .merge(role::router(db.clone(), cache.clone(), config.clone()))
        .merge(product::router(db.clone(), cache.clone(), config.clone()))
        .merge(audit::router(db.clone(), cache.clone(), config.clone()))
        .merge(audit_explorer::router(
            db.clone(),
            cache.clone(),
            config.clone(),
        ))
        .merge(dashboard::router(db.clone(), cache.clone(), config.clone()))
        .merge(upload::router(db.clone(), cache.clone(), config.clone()))
}
