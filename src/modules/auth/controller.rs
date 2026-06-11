use crate::{
    config::AppConfig,
    errors::{AppError, AppJson},
    infra::cache::Cache,
    middleware::auth::CurrentUser,
    modules::auth::schemas::{
        AuthResponse, JwksResponse, LoginRequest, RefreshRequest, SimpleStatusResponse,
        UserMeResponse,
    },
    modules::auth::service::AuthModuleService,
};
use axum::{extract::State, Extension, Json};
use sea_orm::DatabaseConnection;

pub async fn login_handler(
    State(state): State<(DatabaseConnection, Cache, AppConfig)>,
    AppJson(payload): AppJson<LoginRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let (db, cache, config) = state;
    let auth_data = AuthModuleService::login(payload, &db, &cache, &config).await?;
    Ok(Json(auth_data))
}

pub async fn get_me_handler(
    State(state): State<(DatabaseConnection, Cache, AppConfig)>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<UserMeResponse>, AppError> {
    let (db, _, config) = state;
    let me_data = AuthModuleService::get_me(&current_user.id, &db, &config).await?;
    Ok(Json(me_data))
}

pub async fn logout_handler(
    State(state): State<(DatabaseConnection, Cache, AppConfig)>,
    Extension(current_user): Extension<CurrentUser>,
) -> Result<Json<SimpleStatusResponse>, AppError> {
    let (_, cache, config) = state;
    let response = AuthModuleService::logout(&current_user.id, &cache, &config).await?;
    Ok(Json(response))
}

pub async fn refresh_handler(
    State(state): State<(DatabaseConnection, Cache, AppConfig)>,
    AppJson(payload): AppJson<RefreshRequest>,
) -> Result<Json<AuthResponse>, AppError> {
    let (db, cache, config) = state;
    let auth_data =
        AuthModuleService::refresh(&payload.refresh_token, &db, &cache, &config).await?;
    Ok(Json(auth_data))
}

pub async fn jwks_handler() -> Json<JwksResponse> {
    Json(JwksResponse { keys: vec![] })
}
