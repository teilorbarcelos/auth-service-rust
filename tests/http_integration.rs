use auth_service_rust::{
    config::AppConfig,
    infra::{auth::AuthService, cache::Cache, database},
    models,
    modules,
};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};
use tower::ServiceExt;

async fn build_app() -> (axum::Router, AppConfig) {
    let config = AppConfig::load();
    let db = database::connect(&config.database_url)
        .await
        .expect("Failed to connect to DB");
    let cache = Cache::new(&config.redis_url);

    let api_router = modules::app_router(db.clone(), cache.clone(), config.clone());
    let obs_router = modules::observability::router(db.clone(), cache.clone());

    let app = axum::Router::new()
        .merge(api_router)
        .merge(obs_router);

    (app, config)
}

/// Cria um usuário único por teste para evitar race conditions
async fn create_http_test_user(db: &DatabaseConnection) -> (String, String, String) {
    let uid: String = uuid::Uuid::new_v4().to_string().chars().take(32).collect();
    let email = format!("http-{}@test.com", uid);
    let password = "test-pass-123";

    let password_hash = AuthService::hash_password(password).unwrap();
    let auth_id = format!("ha{}", &uid[..30]);
    let auth = models::auth::ActiveModel {
        id: Set(auth_id.clone()),
        password: Set(Some(password_hash)),
        active: Set(true),
        is_deleted: Set(Some(false)),
        deleted_at: Set(None),
        created_at: Set(chrono::Utc::now().into()),
        updated_at: Set(chrono::Utc::now().into()),
        ..Default::default()
    };
    auth.insert(db).await.expect("create auth");

    let user_id = format!("hu{}", &uid[..30]);
    let user = models::user::ActiveModel {
        id: Set(user_id.clone()),
        name: Set("HTTP Test User".to_string()),
        email: Set(email.clone()),
        id_role: Set("administrator".to_string()),
        id_auth: Set(Some(auth_id)),
        active: Set(true),
        is_deleted: Set(Some(false)),
        deleted_at: Set(None),
        created_at: Set(chrono::Utc::now().into()),
        updated_at: Set(chrono::Utc::now().into()),
        ..Default::default()
    };
    user.insert(db).await.expect("create user");

    (email, password.to_string(), user_id)
}

#[tokio::test]
async fn test_health_endpoint() {
    let (app, _) = build_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/health")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_liveness_endpoint() {
    let (app, _) = build_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/liveness")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_login_endpoint_invalid_json() {
    let (app, _) = build_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/login")
                .method("POST")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"invalid": "json"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    // Missing email + password should fail
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_login_endpoint_wrong_credentials() {
    let (app, _) = build_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/login")
                .method("POST")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"email":"nonexistent@test.com","password":"wrong"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_login_endpoint_success() {
    let (app, _) = build_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/login")
                .method("POST")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    r#"{"email":"admin@email.com","password":"admin@123"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap())
        .unwrap();

    assert!(body.get("token").and_then(|t| t.as_str()).is_some());
    assert!(body.get("refreshToken").and_then(|t| t.as_str()).is_some());
    assert_eq!(
        body["user"]["email"].as_str(),
        Some("admin@email.com")
    );
}

#[tokio::test]
async fn test_me_endpoint_requires_auth() {
    let (app, _) = build_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/me")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_me_endpoint_with_token() {
    let (app, config) = build_app().await;
    let db = database::connect(&config.database_url).await.unwrap();
    let (_email, password, _user_id) = create_http_test_user(&db).await;

    // Login with test user
    let body_str = serde_json::json!({"email": _email, "password": password}).to_string();
    let login = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/login")
                .method("POST")
                .header("Content-Type", "application/json")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);

    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(login.into_body(), usize::MAX)
            .await
            .unwrap())
        .unwrap();
    let token = body["token"].as_str().unwrap().to_string();

    // Now call /me with the token - build a new app instance
    let (app2, _) = build_app().await;
    let response = app2
        .oneshot(
            Request::builder()
                .uri("/v1/auth/me")
                .method("GET")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_jwks_endpoint() {
    let (app, _) = build_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/.well-known/jwks.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap())
        .unwrap();

    assert!(body.get("keys").is_some());
    assert_eq!(body["keys"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn test_route_not_found() {
    let (app, _) = build_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/nonexistent")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_ready_endpoint() {
    let (app, _) = build_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    // Should be OK since DB and Redis are running
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_refresh_endpoint_invalid_token() {
    let (app, _) = build_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/refresh")
                .method("POST")
                .header("Content-Type", "application/json")
                .body(Body::from(r#"{"refreshToken":"invalid-token"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_logout_endpoint_requires_auth() {
    let (app, _) = build_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/logout")
                .method("POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_login_endpoint_missing_content_type() {
    let (app, _) = build_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/login")
                .method("POST")
                .body(Body::from(
                    r#"{"email":"admin@email.com","password":"admin@123"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_login_without_body() {
    let (app, _) = build_app().await;

    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/login")
                .method("POST")
                .header("Content-Type", "application/json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_login_then_logout() {
    let (app, config) = build_app().await;
    let db = database::connect(&config.database_url).await.unwrap();
    let (_email, password, _user_id) = create_http_test_user(&db).await;

    let body_str = serde_json::json!({"email": _email, "password": password}).to_string();
    let login = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/login")
                .method("POST")
                .header("Content-Type", "application/json")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(login.into_body(), usize::MAX)
            .await
            .unwrap())
        .unwrap();
    let token = body["token"].as_str().unwrap().to_string();

    let (app2, _) = build_app().await;
    let logout = app2
        .oneshot(
            Request::builder()
                .uri("/v1/auth/logout")
                .method("POST")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout.status(), StatusCode::OK);

    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(logout.into_body(), usize::MAX)
            .await
            .unwrap())
        .unwrap();
    assert!(body.get("status").and_then(|s| s.as_bool()).unwrap_or(false));
}

#[tokio::test]
async fn test_login_then_refresh() {
    let (app, config) = build_app().await;
    let db = database::connect(&config.database_url).await.unwrap();
    let (_email, password, _user_id) = create_http_test_user(&db).await;

    let body_str = serde_json::json!({"email": _email, "password": password}).to_string();
    let login = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/login")
                .method("POST")
                .header("Content-Type", "application/json")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login.status(), StatusCode::OK);
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(login.into_body(), usize::MAX)
            .await
            .unwrap())
        .unwrap();
    let refresh_token = body["refreshToken"].as_str().unwrap().to_string();

    let (app2, _) = build_app().await;
    let refresh = app2
        .oneshot(
            Request::builder()
                .uri("/v1/auth/refresh")
                .method("POST")
                .header("Content-Type", "application/json")
                .body(Body::from(
                    serde_json::json!({"refreshToken": refresh_token}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refresh.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_me_with_invalid_bearer_format() {
    let (app, _) = build_app().await;

    // Authorization header without Bearer prefix
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/me")
                .method("GET")
                .header("Authorization", "Token invalid-format")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_me_with_fake_bearer_token() {
    let (app, _) = build_app().await;

    // Valid Bearer format but fake token
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/me")
                .method("GET")
                .header("Authorization", "Bearer invalid-token-that-is-fake")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_revoked_token_rejected() {
    let (app, config) = build_app().await;
    let db = database::connect(&config.database_url).await.unwrap();
    let (_email, password, user_id) = create_http_test_user(&db).await;

    // Login
    let body_str = serde_json::json!({"email": _email, "password": password}).to_string();
    let login = app
        .oneshot(
            Request::builder()
                .uri("/v1/auth/login")
                .method("POST")
                .header("Content-Type", "application/json")
                .body(Body::from(body_str))
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(login.into_body(), usize::MAX)
            .await
            .unwrap())
        .unwrap();
    let token = body["token"].as_str().unwrap().to_string();

    // Revoke sessions directly in Redis
    let cache = Cache::new(&config.redis_url);
    cache.invalidate_user_sessions(&user_id).await.unwrap();

    // Now try to use the revoked token - should get 401
    let (app2, _) = build_app().await;
    let response = app2
        .oneshot(
            Request::builder()
                .uri("/v1/auth/me")
                .method("GET")
                .header("Authorization", format!("Bearer {}", token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_ready_with_invalid_cache() {
    use auth_service_rust::infra::database;

    let cache = Cache::new("redis://127.0.0.1:16379");
    let config = AppConfig::load();
    let db = database::connect(&config.database_url).await.unwrap();
    let obs_router = modules::observability::router(db, cache);

    let response = obs_router
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert!(response.status() == StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn test_backend_rust_crate_name_not_used() {
    // Verify the crate was renamed from backend-rust
    assert_eq!(
        std::env!("CARGO_PKG_NAME"),
        "auth-service-rust",
        "Crate should be renamed to auth-service-rust"
    );
}
