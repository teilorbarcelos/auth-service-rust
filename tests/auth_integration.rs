use auth_service_rust::{
    config::AppConfig,
    errors::AppError,
    infra::{auth::AuthService, cache::Cache},
    middleware::auth::CurrentUser,
    modules::auth::{
        schemas::LoginRequest,
        service::AuthModuleService,
    },
};
use axum::response::IntoResponse;
use sea_orm::{ConnectionTrait, DatabaseBackend, DatabaseConnection, Statement};

async fn db(config: &AppConfig) -> DatabaseConnection {
    sea_orm::Database::connect(&config.database_url).await.unwrap()
}

async fn exec(db: &DatabaseConnection, sql: &str, values: Vec<sea_orm::Value>) {
    db.execute(Statement::from_sql_and_values(DatabaseBackend::Postgres, sql, values)).await.unwrap();
}

async fn create_test_user(db: &DatabaseConnection, config: &AppConfig, tag: &str) -> (String, String, String) {
    let p = &config.profile;
    let uid: String = uuid::Uuid::new_v4().to_string().chars().take(32).collect();
    let email = format!("test-{}-{}@test.com", tag, uid);
    let password = "test-pass-123";
    let hash = AuthService::hash_password(password).unwrap();
    let auth_id = format!("at{}", &uid[..32]);
    let user_id = format!("us{}", &uid[..30]);
    exec(db, &format!(r#"INSERT INTO "{}" (id, password, active, is_deleted, created_at, updated_at) VALUES ($1, $2, true, false, NOW(), NOW())"#, p.table_auth), vec![auth_id.clone().into(), hash.into()]).await;
    exec(db, &format!(r#"INSERT INTO "{}" (id, name, email, id_role, id_auth, active, is_deleted, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, true, false, NOW(), NOW())"#, p.table_user), vec![user_id.clone().into(), format!("Test User {}", tag).into(), email.clone().into(), "administrator".into(), auth_id.into()]).await;
    (email, password.to_string(), user_id)
}

async fn delete_user(db: &DatabaseConnection, config: &AppConfig, user_id: &str) {
    let p = &config.profile;
    let row = db.query_one(Statement::from_sql_and_values(DatabaseBackend::Postgres, format!(r#"SELECT id_auth FROM "{}" WHERE id = $1"#, p.table_user), vec![user_id.into()])).await.ok().flatten();
    let auth_id = row.and_then(|r| r.try_get::<Option<String>>("", "id_auth").ok().flatten());
    let _ = exec(db, &format!(r#"DELETE FROM "{}" WHERE id = $1"#, p.table_user), vec![user_id.into()]).await;
    if let Some(aid) = auth_id {
        let _ = exec(db, &format!(r#"DELETE FROM "{}" WHERE id = $1"#, p.table_auth), vec![aid.into()]).await;
    }
}

#[tokio::test]
async fn test_login_invalid_credentials() {
    let config = AppConfig::load();
    let cache = Cache::new(&config.redis_url, config.profile.clone());
    let result = AuthModuleService::login(
        LoginRequest { email: "nonexistent@test.com".to_string(), password: "wrongpass".to_string() },
        &db(&config).await, &cache, &config,
    ).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().message().contains("Credenciais inválidas"));
}

#[tokio::test]
async fn test_login_wrong_password() {
    let config = AppConfig::load();
    let cache = Cache::new(&config.redis_url, config.profile.clone());
    let result = AuthModuleService::login(
        LoginRequest { email: "admin@email.com".to_string(), password: "wrong-password".to_string() },
        &db(&config).await, &cache, &config,
    ).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().message(), "Credenciais inválidas");
}

#[tokio::test]
async fn test_token_generation() {
    let config = AppConfig::load();
    let (access, refresh) = AuthService::generate_tokens("test-id", "test@test.com", "admin", &config.jwt_secret, 3600, 0, &[], &config.profile).unwrap();
    let claims = AuthService::verify_token(&access, &config.jwt_secret).unwrap();
    assert_eq!(claims.sub, "test-id");
    assert_eq!(claims.email, "test@test.com");
    assert_eq!(claims.role, "admin");
    let rc = AuthService::verify_token(&refresh, &config.jwt_secret).unwrap();
    assert_eq!(rc.sub, "test-id");
}

#[tokio::test]
async fn test_token_claims() {
    let config = AppConfig::load();
    let (access, _) = AuthService::generate_tokens("sub", "e@t.com", "role", &config.jwt_secret, 3600, 0, &[], &config.profile).unwrap();
    let c = AuthService::verify_token(&access, &config.jwt_secret).unwrap();
    assert_eq!(c.sub, "sub");
    assert!(c.exp > c.iat);
}

#[tokio::test]
async fn test_password_hashing() {
    let hash = AuthService::hash_password("mypass").unwrap();
    assert!(AuthService::verify_password("mypass", &hash).unwrap());
    assert!(!AuthService::verify_password("wrong", &hash).unwrap());
}

#[tokio::test]
async fn test_session_management() {
    let config = AppConfig::load();
    let cache = Cache::new(&config.redis_url, config.profile.clone());
    let uid = format!("sess-{}", uuid::Uuid::new_v4());
    cache.create_session(&uid, "access:tok", 60).await.unwrap();
    assert!(cache.validate_session(&uid, "access:tok").await.unwrap());
    cache.invalidate_user_sessions(&uid).await.unwrap();
    assert!(!cache.validate_session(&uid, "access:tok").await.unwrap());
}

#[tokio::test]
async fn test_cache_sets() {
    let config = AppConfig::load();
    let cache = Cache::new(&config.redis_url, config.profile.clone());
    let key = format!("set-{}", uuid::Uuid::new_v4());
    assert!(!cache.key_exists(&key).await.unwrap());
    cache.add_to_set(&key, &["a:1".into(), "b:2".into()], 60).await.unwrap();
    assert!(cache.key_exists(&key).await.unwrap());
    assert!(cache.is_set_member(&key, "a:1").await.unwrap());
    assert!(!cache.is_set_member(&key, "c:3").await.unwrap());
}

#[tokio::test]
async fn test_current_user() {
    let u = CurrentUser { id: "1".into(), email: "a@b.com".into(), role: "admin".into() };
    assert_eq!(u.id, "1");
}

#[tokio::test]
async fn test_wrong_secret() {
    let config = AppConfig::load();
    let (t, _) = AuthService::generate_tokens("u", "u@t.com", "r", &config.jwt_secret, 3600, 0, &[], &config.profile).unwrap();
    assert!(AuthService::verify_token(&t, "different-secret").is_err());
}

#[tokio::test]
async fn test_app_error_conversion() {
let cases = vec![
    AppError::BadRequest("x".into()),
    AppError::Unauthorized("x".into()),
    AppError::Forbidden("x".into()),
    AppError::NotFound("x".into()),
    AppError::Conflict("x".into()),
    AppError::Internal("x".into()),
];
for e in cases {
    let msg = e.message();
    assert!(!msg.is_empty());
}
for e in vec![
    AppError::BadRequest("x".into()),
    AppError::Unauthorized("x".into()),
    AppError::Forbidden("x".into()),
    AppError::NotFound("x".into()),
    AppError::Conflict("x".into()),
    AppError::Internal("x".into()),
] {
    assert!(!e.into_response().status().is_success());
}
}

#[tokio::test]
async fn test_error_display() {
    assert_eq!(format!("{}", AppError::BadRequest("msg".into())), "msg");
}

#[tokio::test]
async fn test_from_conversions() {
    let de = sea_orm::DbErr::Custom("db".into());
    assert!(AppError::from(de).message().contains("Erro interno"));
    let be = bcrypt::BcryptError::InvalidCost("1".into());
    assert!(AppError::from(be).message().contains("Erro de criptografia"));
    let je = jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::ExpiredSignature);
    assert!(AppError::from(je).message().contains("Token JWT inválido"));
}

#[tokio::test]
async fn test_app_json_rejection() {
    use auth_service_rust::errors::AppJson;
    use axum::body::Body;
    use axum::extract::FromRequest;
    use axum::http::Request;
    let req = Request::builder().method("POST").body(Body::from("{}")).unwrap();
    assert!(AppJson::<LoginRequest>::from_request(req, &()).await.is_err());
    let req = Request::builder().method("POST").header("Content-Type", "application/json").body(Body::from("{invalid}")).unwrap();
    assert!(AppJson::<LoginRequest>::from_request(req, &()).await.is_err());
    let req = Request::builder().method("POST").header("Content-Type", "application/json").body(Body::from(r#"{"email":"a@b.com","password":"123"}"#)).unwrap();
    assert!(AppJson::<LoginRequest>::from_request(req, &()).await.is_ok());
}

#[tokio::test]
async fn test_login_admin_success() {
    let config = AppConfig::load();
    if config.profile.name != "rust" { return; } // only works with Rust DB
    let cache = Cache::new(&config.redis_url, config.profile.clone());
    let result = AuthModuleService::login(
        LoginRequest { email: "admin@email.com".to_string(), password: "admin@123".to_string() },
        &db(&config).await, &cache, &config,
    ).await;
    assert!(result.is_ok(), "Admin login should work with seeded DB");
}

#[tokio::test]
async fn test_login_then_get_me() {
    let config = AppConfig::load();
    let cache = Cache::new(&config.redis_url, config.profile.clone());
    let d = db(&config).await;
    let (email, password, user_id) = create_test_user(&d, &config, "me").await;
    let login = AuthModuleService::login(LoginRequest { email, password }, &d, &cache, &config).await.unwrap();
    let me = AuthModuleService::get_me(&login.user.id, &d, &config).await.unwrap();
    assert_eq!(me.user.id, login.user.id);
    delete_user(&d, &config, &user_id).await;
}

#[tokio::test]
async fn test_login_then_logout() {
    let config = AppConfig::load();
    let cache = Cache::new(&config.redis_url, config.profile.clone());
    let d = db(&config).await;
    let (email, password, user_id) = create_test_user(&d, &config, "lo").await;
    let login = AuthModuleService::login(LoginRequest { email, password }, &d, &cache, &config).await.unwrap();
    let result = AuthModuleService::logout(&login.user.id, &cache, &config).await.unwrap();
    assert!(result.status);
    delete_user(&d, &config, &user_id).await;
}

#[tokio::test]
async fn test_login_then_refresh() {
    let config = AppConfig::load();
    let cache = Cache::new(&config.redis_url, config.profile.clone());
    let d = db(&config).await;
    let (email, password, user_id) = create_test_user(&d, &config, "rf").await;
    let login = AuthModuleService::login(LoginRequest { email, password }, &d, &cache, &config).await.unwrap();
    let refreshed = AuthModuleService::refresh(&login.refresh_token, &d, &cache, &config).await.unwrap();
    assert!(!refreshed.token.is_empty());
    delete_user(&d, &config, &user_id).await;
}

#[tokio::test]
async fn test_get_me_nonexistent() {
    let config = AppConfig::load();
    let result = AuthModuleService::get_me("no-such-id", &db(&config).await, &config).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().message(), "Usuário não encontrado");
}

#[tokio::test]
async fn test_login_forbidden_inactive_user() {
    let config = AppConfig::load();
    let cache = Cache::new(&config.redis_url, config.profile.clone());
    let d = db(&config).await;
    let p = &config.profile;
    let uid: String = uuid::Uuid::new_v4().to_string().chars().take(32).collect();
    let email = format!("inact-{}@test.com", uid);
    let hash = AuthService::hash_password("test-pass").unwrap();
    let auth_id = format!("ai{}", &uid[..30]);
    let user_id = format!("ui{}", &uid[..30]);
    exec(&d, &format!(r#"INSERT INTO "{}" (id, password, active, created_at, updated_at) VALUES ($1, $2, true, NOW(), NOW())"#, p.table_auth), vec![auth_id.clone().into(), hash.into()]).await;
    exec(&d, &format!(r#"INSERT INTO "{}" (id, name, email, id_role, id_auth, active, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, false, NOW(), NOW())"#, p.table_user), vec![user_id.clone().into(), "Inactive".into(), email.clone().into(), "administrator".into(), auth_id.into()]).await;
    let result = AuthModuleService::login(LoginRequest { email, password: "test-pass".to_string() }, &d, &cache, &config).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().message(), "Usuário inativo. Login não permitido.");
    delete_user(&d, &config, &user_id).await;
}

#[tokio::test]
async fn test_login_inactive_role() {
    let config = AppConfig::load();
    let cache = Cache::new(&config.redis_url, config.profile.clone());
    let d = db(&config).await;
    let p = &config.profile;
    let uid: String = uuid::Uuid::new_v4().to_string().chars().take(32).collect();
    let role_id = format!("tr-{}", &uid[..28]);
    exec(&d, &format!(r#"INSERT INTO "{}" (id, name, description, active, is_deleted, created_at, updated_at) VALUES ($1, $2, $3, false, false, NOW(), NOW())"#, p.table_role), vec![role_id.clone().into(), "Inactive".into(), "Test".into()]).await;
    let email = format!("ir-{}@test.com", uid);
    let hash = AuthService::hash_password("test-pass").unwrap();
    let auth_id = format!("ai{}", &uid[..30]);
    let user_id = format!("ui{}", &uid[..30]);
    exec(&d, &format!(r#"INSERT INTO "{}" (id, password, active, created_at, updated_at) VALUES ($1, $2, true, NOW(), NOW())"#, p.table_auth), vec![auth_id.clone().into(), hash.into()]).await;
    let role_id_c = role_id.clone();
    let auth_id_c = auth_id.clone();
    exec(&d, &format!(r#"INSERT INTO "{}" (id, name, email, id_role, id_auth, active, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, true, NOW(), NOW())"#, p.table_user), vec![user_id.clone().into(), "User".into(), email.clone().into(), role_id_c.into(), auth_id_c.into()]).await;
    let result = AuthModuleService::login(LoginRequest { email, password: "test-pass".to_string() }, &d, &cache, &config).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().message(), "Perfil de acesso inativo. Login não permitido.");
    exec(&d, &format!(r#"DELETE FROM "{}" WHERE id = $1"#, p.table_user), vec![user_id.clone().into()]).await;
    exec(&d, &format!(r#"DELETE FROM "{}" WHERE id = $1"#, p.table_auth), vec![auth_id.into()]).await;
    exec(&d, &format!(r#"DELETE FROM "{}" WHERE id = $1"#, p.table_role), vec![role_id.into()]).await;
}

#[tokio::test]
async fn test_login_missing_auth() {
    let config = AppConfig::load();
    let cache = Cache::new(&config.redis_url, config.profile.clone());
    let d = db(&config).await;
    let p = &config.profile;
    let uid: String = uuid::Uuid::new_v4().to_string().chars().take(32).collect();
    let email = format!("na-{}@test.com", uid);
    let hash = AuthService::hash_password("test-pass").unwrap();
    let auth_id = format!("na{}", &uid[..30]);
    let user_id = format!("nu{}", &uid[..30]);
    exec(&d, &format!(r#"INSERT INTO "{}" (id, password, active, created_at, updated_at) VALUES ($1, $2, false, NOW(), NOW())"#, p.table_auth), vec![auth_id.clone().into(), hash.into()]).await;
    exec(&d, &format!(r#"INSERT INTO "{}" (id, name, email, id_role, id_auth, active, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, true, NOW(), NOW())"#, p.table_user), vec![user_id.clone().into(), "User".into(), email.clone().into(), "administrator".into(), auth_id.into()]).await;
    let result = AuthModuleService::login(LoginRequest { email, password: "test-pass".to_string() }, &d, &cache, &config).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().message(), "Credenciais de acesso inativas.");
    delete_user(&d, &config, &user_id).await;
}

#[tokio::test]
async fn test_cache_operations() {
    let config = AppConfig::load();
    let cache = Cache::new(&config.redis_url, config.profile.clone());
    cache.delete_key(&format!("k-{}", uuid::Uuid::new_v4())).await.unwrap();
    cache.delete_session("nonexistent", "t").await.unwrap();
    assert!(!cache.is_set_member(&format!("s-{}", uuid::Uuid::new_v4()), "x").await.unwrap());
}

#[tokio::test]
async fn test_refresh_nonexistent_session() {
    let config = AppConfig::load();
    let cache = Cache::new(&config.redis_url, config.profile.clone());
    let (_, refresh) = AuthService::generate_tokens("nonexistent", "n@t.com", "r", &config.jwt_secret, 900, 0, &[], &config.profile).unwrap();
    let result = AuthModuleService::refresh(&refresh, &db(&config).await, &cache, &config).await;
    assert!(result.is_err());
    if config.profile.manage_sessions {
        assert_eq!(result.unwrap_err().message(), "Sessão revogada ou expirada");
    }
}

#[tokio::test]
async fn test_rate_limit() {
    let config = AppConfig::load();
    let cache = Cache::new(&config.redis_url, config.profile.clone());
    let key = format!("rl-{}", uuid::Uuid::new_v4());
    let (allowed, _, _) = cache.check_rate_limit(&key, 10, 60).await.unwrap();
    assert!(allowed);
}
