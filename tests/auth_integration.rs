use auth_service_rust::{
    config::AppConfig,
    infra::{auth::AuthService, cache::Cache},
    middleware::auth::CurrentUser,
    modules::auth::{schemas::LoginRequest, service::AuthModuleService},
};
use sea_orm::DatabaseConnection;

async fn connect_db(config: &AppConfig) -> DatabaseConnection {
    sea_orm::Database::connect(&config.database_url)
        .await
        .expect("Failed to connect to database")
}

#[tokio::test]
async fn test_login_invalid_credentials() {
    let config = AppConfig::load();
    let db = connect_db(&config).await;
    let cache = Cache::new(&config.redis_url);

    let payload = LoginRequest {
        email: "nonexistent@test.com".to_string(),
        password: "wrongpass".to_string(),
    };

    let result = AuthModuleService::login(payload, &db, &cache, &config).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().message(), "Credenciais inválidas");
}

#[tokio::test]
async fn test_token_generation_and_verification() {
    let config = AppConfig::load();

    let (access, refresh) = AuthService::generate_tokens(
        "test-user-id",
        "test@example.com",
        "admin",
        &config.jwt_secret,
        3600,
    )
    .expect("Should generate tokens");

    let claims =
        AuthService::verify_token(&access, &config.jwt_secret).expect("Should verify token");

    assert_eq!(claims.sub, "test-user-id");
    assert_eq!(claims.email, "test@example.com");
    assert_eq!(claims.role, "admin");

    let refresh_claims = AuthService::verify_token(&refresh, &config.jwt_secret)
        .expect("Should verify refresh token");

    assert_eq!(refresh_claims.sub, "test-user-id");
}

#[tokio::test]
async fn test_token_expired() {
    let config = AppConfig::load();

    let (token, _) =
        AuthService::generate_tokens("user-id", "user@test.com", "role", &config.jwt_secret, 0)
            .expect("Should generate token");

    // Sleep briefly to ensure token is expired
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let result = AuthService::verify_token(&token, &config.jwt_secret);
    assert!(result.is_err());
}

#[tokio::test]
async fn test_password_hashing_and_verification() {
    let password = "my-secure-password-123";

    let hash = AuthService::hash_password(password).expect("Should hash password");

    assert!(AuthService::verify_password(password, &hash).expect("Should verify"));

    assert!(!AuthService::verify_password("wrong-password", &hash).expect("Should not verify"));
}

#[tokio::test]
async fn test_session_invalidation() {
    let config = AppConfig::load();
    let cache = Cache::new(&config.redis_url);
    let user_id = format!("test-session-{}", uuid::Uuid::new_v4());

    cache
        .create_session(&user_id, "access:test-token", 60)
        .await
        .expect("Should create session");

    let valid = cache
        .validate_session(&user_id, "access:test-token")
        .await
        .expect("Should validate session");
    assert!(valid);

    cache
        .invalidate_user_sessions(&user_id)
        .await
        .expect("Should invalidate sessions");

    let invalid = cache
        .validate_session(&user_id, "access:test-token")
        .await
        .expect("Should check session");
    assert!(!invalid);
}

#[tokio::test]
async fn test_key_exists_and_set_members() {
    let config = AppConfig::load();
    let cache = Cache::new(&config.redis_url);
    let key = format!("test-perm-{}", uuid::Uuid::new_v4());

    let exists = cache.key_exists(&key).await.unwrap();
    assert!(!exists);

    cache
        .add_to_set(
            &key,
            &[String::from("user:view"), String::from("product:create")],
            60,
        )
        .await
        .unwrap();

    let exists = cache.key_exists(&key).await.unwrap();
    assert!(exists);

    assert!(cache.is_set_member(&key, "user:view").await.unwrap());
    assert!(cache.is_set_member(&key, "product:create").await.unwrap());
    assert!(!cache.is_set_member(&key, "admin:delete").await.unwrap());
}

#[tokio::test]
async fn test_current_user_creation() {
    let user = CurrentUser {
        id: "user-1".to_string(),
        email: "admin@test.com".to_string(),
        role: "administrator".to_string(),
    };

    assert_eq!(user.id, "user-1");
    assert_eq!(user.email, "admin@test.com");
    assert_eq!(user.role, "administrator");
}
