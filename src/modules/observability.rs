use crate::infra::cache::Cache;
use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use sea_orm::DatabaseConnection;
use serde_json::json;

async fn liveness_handler() -> Json<serde_json::Value> {
    Json(json!({ "status": "UP" }))
}

async fn ready_handler(
    State((db, cache)): State<(DatabaseConnection, Cache)>,
) -> impl axum::response::IntoResponse {
    let db_ok = db.ping().await.is_ok();
    let cache_ok = if let Ok(mut conn) = cache.pool.get().await {
        redis::cmd("PING")
            .query_async::<_, String>(&mut conn)
            .await
            .is_ok()
    } else {
        false
    };

    let status = if db_ok && cache_ok { "UP" } else { "DOWN" };
    let code = if db_ok && cache_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        code,
        Json(json!({
            "status": status,
            "database": if db_ok { "UP" } else { "DOWN" },
            "cache": if cache_ok { "UP" } else { "DOWN" }
        })),
    )
}

pub fn router(db: DatabaseConnection, cache: Cache) -> Router {
    let state = (db, cache);

    Router::new()
        .route("/health", get(liveness_handler))
        .route("/liveness", get(liveness_handler))
        .route("/ready", get(ready_handler))
        .with_state(state)
}
