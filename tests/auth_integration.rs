use auth_service_rust::{
    config::AppConfig,
    errors::AppError,
    infra::{auth::AuthService, cache::Cache},
    middleware::auth::CurrentUser,
    modules::auth::{schemas::LoginRequest, service::AuthModuleService},
};
use axum::response::IntoResponse;
use sea_orm::{ActiveModelTrait, DatabaseConnection, EntityTrait, Set};

async fn connect_db(config: &AppConfig) -> DatabaseConnection {
    sea_orm::Database::connect(&config.database_url)
        .await
        .expect("Failed to connect to database")
}

/// Cria um usuário temporário para testes isolados (cada teste tem seu próprio user).
/// Retorna o email e a senha criados.
async fn create_test_user(db: &DatabaseConnection, tag: &str) -> (String, String, String) {
    let uid: String = uuid::Uuid::new_v4().to_string().chars().take(32).collect();
    let email = format!("test-{}-{}@test.com", tag, uid);
    let password = "test-pass-123";

    let password_hash = AuthService::hash_password(password).unwrap();

    let auth_id = format!("at{}", &uid[..32]);
    let auth = auth_service_rust::models::auth::ActiveModel {
        id: Set(auth_id.clone()),
        password: Set(Some(password_hash)),
        active: Set(true),
        is_deleted: Set(Some(false)),
        deleted_at: Set(None),
        created_at: Set(chrono::Utc::now().into()),
        updated_at: Set(chrono::Utc::now().into()),
        ..Default::default()
    };
    auth.insert(db).await.expect("Failed to create auth record");

    let user_id = format!("us{}", &uid[..30]);
    let user = auth_service_rust::models::user::ActiveModel {
        id: Set(user_id.clone()),
        name: Set(format!("Test User {}", tag)),
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
    user.insert(db).await.expect("Failed to create user record");

    (email, password.to_string(), user_id)
}

async fn delete_test_user(db: &DatabaseConnection, user_id: &str) {
    if let Some(u) = auth_service_rust::models::user::Entity::find_by_id(user_id.to_string())
        .one(db)
        .await
        .ok()
        .flatten()
    {
        if let Some(auth_id) = u.id_auth {
            let _ = auth_service_rust::models::auth::Entity::delete_by_id(auth_id)
                .exec(db)
                .await;
        }
        let _ = auth_service_rust::models::user::Entity::delete_by_id(user_id)
            .exec(db)
            .await;
    }
}

// ─── Tests that DON'T modify shared state ─────────────────────────

#[tokio::test]
async fn test_login_invalid_credentials() {
    let config = AppConfig::load();
    let db = connect_db(&config).await;

    let payload = LoginRequest {
        email: "nonexistent@test.com".to_string(),
        password: "wrongpass".to_string(),
    };

    let cache = Cache::new(&config.redis_url);
    let result = AuthModuleService::login(payload, &db, &cache, &config).await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .message()
        .contains("Credenciais inválidas"));
}

#[tokio::test]
async fn test_login_wrong_password() {
    let config = AppConfig::load();
    let db = connect_db(&config).await;

    let payload = LoginRequest {
        email: "admin@email.com".to_string(),
        password: "wrong-password".to_string(),
    };

    let cache = Cache::new(&config.redis_url);
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

    let refresh_claims =
        AuthService::verify_token(&refresh, &config.jwt_secret).expect("Should verify refresh");
    assert_eq!(refresh_claims.sub, "test-user-id");
}

#[tokio::test]
async fn test_token_claims_structure() {
    let config = AppConfig::load();

    let (access, _) = AuthService::generate_tokens(
        "test-sub",
        "test@test.com",
        "admin",
        &config.jwt_secret,
        3600,
    )
    .expect("Should generate token");

    let claims = AuthService::verify_token(&access, &config.jwt_secret).expect("Should verify");

    assert_eq!(claims.sub, "test-sub");
    assert_eq!(claims.email, "test@test.com");
    assert_eq!(claims.role, "admin");
    assert!(claims.exp > claims.iat);
    assert!(claims.iat > 0);
}

#[tokio::test]
async fn test_password_hashing() {
    let password = "my-secure-password-123";

    let hash = AuthService::hash_password(password).expect("Should hash");
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

    assert!(cache
        .validate_session(&user_id, "access:test-token")
        .await
        .unwrap());

    cache
        .invalidate_user_sessions(&user_id)
        .await
        .expect("Should invalidate");

    assert!(!cache
        .validate_session(&user_id, "access:test-token")
        .await
        .unwrap());
}

#[tokio::test]
async fn test_key_exists_and_set_members() {
    let config = AppConfig::load();
    let cache = Cache::new(&config.redis_url);
    let key = format!("test-perm-{}", uuid::Uuid::new_v4());

    assert!(!cache.key_exists(&key).await.unwrap());

    cache
        .add_to_set(
            &key,
            &[String::from("user:view"), String::from("product:create")],
            60,
        )
        .await
        .unwrap();

    assert!(cache.key_exists(&key).await.unwrap());
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

#[tokio::test]
async fn test_generate_tokens_wrong_secret() {
    let config = AppConfig::load();

    let (token, _) =
        AuthService::generate_tokens("user", "user@test.com", "role", &config.jwt_secret, 3600)
            .expect("Should generate");

    // Verify with wrong secret should fail
    let result = AuthService::verify_token(&token, "different-secret");
    assert!(result.is_err());
}

// ─── Tests that use isolated test users ─────────────────────────

#[tokio::test]
async fn test_login_success() {
    let config = AppConfig::load();
    let db = connect_db(&config).await;
    let cache = Cache::new(&config.redis_url);

    let (email, password, _user_id) = create_test_user(&db, "success").await;

    let result = AuthModuleService::login(
        LoginRequest {
            email: email.clone(),
            password,
        },
        &db,
        &cache,
        &config,
    )
    .await;
    assert!(result.is_ok(), "Login failed: {:?}", result.err());

    let auth_response = result.unwrap();
    assert!(!auth_response.token.is_empty());
    assert!(!auth_response.refresh_token.is_empty());
    assert_eq!(auth_response.user.email, email);

    // Permissions should be cached in Redis
    let perm_key = format!("session:{}:permissions", auth_response.user.id);
    assert!(cache.key_exists(&perm_key).await.unwrap());

    delete_test_user(&db, &auth_response.user.id).await;
    cache
        .invalidate_user_sessions(&auth_response.user.id)
        .await
        .ok();
}

#[tokio::test]
async fn test_refresh_token_cycle() {
    let config = AppConfig::load();
    let db = connect_db(&config).await;
    let cache = Cache::new(&config.redis_url);

    let (email, password, _user_id) = create_test_user(&db, "refresh").await;

    let login = AuthModuleService::login(
        LoginRequest {
            email: email.clone(),
            password,
        },
        &db,
        &cache,
        &config,
    )
    .await
    .expect("Login should succeed");

    let refresh_token = login.refresh_token.clone();

    let refreshed = AuthModuleService::refresh(&refresh_token, &db, &cache, &config)
        .await
        .expect("Refresh should succeed");

    assert!(!refreshed.token.is_empty());
    assert!(!refreshed.refresh_token.is_empty());

    delete_test_user(&db, &login.user.id).await;
    cache.invalidate_user_sessions(&login.user.id).await.ok();
}

#[tokio::test]
async fn test_get_me_after_login() {
    let config = AppConfig::load();
    let db = connect_db(&config).await;
    let cache = Cache::new(&config.redis_url);

    let (email, password, _user_id) = create_test_user(&db, "getme").await;

    let login = AuthModuleService::login(
        LoginRequest {
            email: email.clone(),
            password,
        },
        &db,
        &cache,
        &config,
    )
    .await
    .expect("Login should succeed");

    let me = AuthModuleService::get_me(&login.user.id, &db)
        .await
        .expect("GetMe should succeed");

    assert_eq!(me.user.id, login.user.id);
    assert_eq!(me.user.email, email);

    delete_test_user(&db, &login.user.id).await;
    cache.invalidate_user_sessions(&login.user.id).await.ok();
}

#[tokio::test]
async fn test_logout_invalidates_session() {
    let config = AppConfig::load();
    let db = connect_db(&config).await;
    let cache = Cache::new(&config.redis_url);

    let (email, password, _user_id) = create_test_user(&db, "logout").await;

    let login = AuthModuleService::login(
        LoginRequest {
            email: email.clone(),
            password,
        },
        &db,
        &cache,
        &config,
    )
    .await
    .expect("Login should succeed");

    let user_id = login.user.id.clone();
    let access_token = login.token.clone();

    let result = AuthModuleService::logout(&user_id, &cache)
        .await
        .expect("Logout should succeed");
    assert!(result.status);

    let session_valid = cache
        .validate_session(&user_id, &format!("access:{}", access_token))
        .await
        .unwrap();
    assert!(!session_valid, "Session should be invalid after logout");

    delete_test_user(&db, &user_id).await;
}

#[tokio::test]
async fn test_app_error_conversion() {
    // Test various AppError conversions match expected responses
    let bad = AppError::BadRequest("bad".to_string());
    assert!(!bad.message().is_empty());
    assert!(!bad.into_response().status().is_success());

    let unauth = AppError::Unauthorized("unauth".to_string());
    assert!(!unauth.message().is_empty());
    assert!(!unauth.into_response().status().is_success());

    let forbidden = AppError::Forbidden("forbidden".to_string());
    assert!(!forbidden.message().is_empty());
    assert!(!forbidden.into_response().status().is_success());

    let not_found = AppError::NotFound("not found".to_string());
    assert!(!not_found.message().is_empty());
    assert!(!not_found.into_response().status().is_success());

    let conflict = AppError::Conflict("conflict".to_string());
    assert!(!conflict.message().is_empty());
    assert!(!conflict.into_response().status().is_success());

    let internal = AppError::Internal("internal".to_string());
    assert!(!internal.message().is_empty());
    assert!(!internal.into_response().status().is_success());
}

#[tokio::test]
async fn test_app_error_display() {
    let err = AppError::BadRequest("test display".to_string());
    assert_eq!(format!("{}", err), "test display");
}

#[tokio::test]
async fn test_app_json_rejection() {
    use auth_service_rust::errors::AppJson;
    use axum::body::Body;
    use axum::extract::FromRequest;
    use axum::http::Request;

    // Missing Content-Type should fail
    let req = Request::builder()
        .method("POST")
        .body(Body::from("{}"))
        .unwrap();
    let res = AppJson::<LoginRequest>::from_request(req, &()).await;
    assert!(res.is_err());

    // Invalid JSON syntax
    let req = Request::builder()
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from("{invalid}"))
        .unwrap();
    let res = AppJson::<LoginRequest>::from_request(req, &()).await;
    assert!(res.is_err());

    // Valid JSON
    let req = Request::builder()
        .method("POST")
        .header("Content-Type", "application/json")
        .body(Body::from(r#"{"email":"a@b.com","password":"123"}"#))
        .unwrap();
    let res = AppJson::<LoginRequest>::from_request(req, &()).await;
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_from_conversions() {
    use sea_orm::DbErr;
    let db_err = DbErr::Custom("db error".to_string());
    let app_err = AppError::from(db_err);
    assert!(app_err.message().contains("Erro interno"));

    let bcrypt_err = bcrypt::BcryptError::InvalidCost("1".to_string());
    let app_err = AppError::from(bcrypt_err);
    assert!(app_err.message().contains("Erro de criptografia"));

    let jwt_err =
        jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::ExpiredSignature);
    let app_err = AppError::from(jwt_err);
    assert!(app_err.message().contains("Token JWT inválido ou expirado"));
}

#[tokio::test]
async fn test_get_me_nonexistent_user() {
    let config = AppConfig::load();
    let db = connect_db(&config).await;

    let result = AuthModuleService::get_me("non-existent-user-id", &db).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().message(), "Usuário não encontrado");
}

#[tokio::test]
async fn test_login_forbidden_inactive_user() {
    let config = AppConfig::load();
    let db = connect_db(&config).await;
    let cache = Cache::new(&config.redis_url);

    let uid: String = uuid::Uuid::new_v4().to_string().chars().take(32).collect();
    let email = format!("inactive-{}@test.com", uid);
    let password = "test-pass";

    // Create user (in the DB) with inactive status
    let password_hash = AuthService::hash_password(password).unwrap();
    let auth_id = format!("ai{}", &uid[..30]);
    let auth = auth_service_rust::models::auth::ActiveModel {
        id: Set(auth_id.clone()),
        password: Set(Some(password_hash)),
        active: Set(true),
        ..Default::default()
    };
    let auth = auth.insert(&db).await.unwrap();

    let user_id = format!("ui{}", &uid[..30]);
    let user = auth_service_rust::models::user::ActiveModel {
        id: Set(user_id.clone()),
        name: Set("Inactive User".to_string()),
        email: Set(email.clone()),
        id_role: Set("administrator".to_string()),
        id_auth: Set(Some(auth.id)),
        active: Set(false),
        ..Default::default()
    };
    user.insert(&db).await.unwrap();

    let payload = LoginRequest {
        email,
        password: password.to_string(),
    };

    let result = AuthModuleService::login(payload, &db, &cache, &config).await;
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert_eq!(err.message(), "Usuário inativo. Login não permitido.");

    // Cleanup
    delete_test_user(&db, &user_id).await;
}

#[tokio::test]
async fn test_login_inactive_role() {
    let config = AppConfig::load();
    let db = connect_db(&config).await;
    let cache = Cache::new(&config.redis_url);

    // Create a test role with active=false
    let role_id = format!(
        "tr-{}",
        uuid::Uuid::new_v4()
            .to_string()
            .chars()
            .take(30)
            .collect::<String>()
    );
    let role = auth_service_rust::models::role::ActiveModel {
        id: Set(role_id.clone()),
        name: Set("Inactive Role".to_string()),
        description: Set("Test".to_string()),
        active: Set(false),
        is_deleted: Set(Some(false)),
        deleted_at: Set(None),
        created_at: Set(chrono::Utc::now().into()),
        updated_at: Set(chrono::Utc::now().into()),
    };
    role.insert(&db).await.unwrap();

    let uid: String = uuid::Uuid::new_v4().to_string().chars().take(32).collect();
    let email = format!("inactive-role-{}@test.com", uid);
    let password = "test-pass";
    let password_hash = AuthService::hash_password(password).unwrap();
    let auth_id = format!("ai{}", &uid[..30]);
    let auth = auth_service_rust::models::auth::ActiveModel {
        id: Set(auth_id.clone()),
        password: Set(Some(password_hash)),
        active: Set(true),
        ..Default::default()
    };
    let auth = auth.insert(&db).await.unwrap();

    let user_id = format!("ui{}", &uid[..30]);
    let user = auth_service_rust::models::user::ActiveModel {
        id: Set(user_id.clone()),
        name: Set("Role Inactive User".to_string()),
        email: Set(email.clone()),
        id_role: Set(role_id.clone()),
        id_auth: Set(Some(auth.id)),
        active: Set(true),
        ..Default::default()
    };
    user.insert(&db).await.unwrap();

    let payload = LoginRequest {
        email,
        password: password.to_string(),
    };

    let result = AuthModuleService::login(payload, &db, &cache, &config).await;
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().message(),
        "Perfil de acesso inativo. Login não permitido."
    );

    // Cleanup
    let _ = auth_service_rust::models::user::Entity::delete_by_id(&user_id)
        .exec(&db)
        .await;
    let _ = auth_service_rust::models::auth::Entity::delete_by_id(&auth_id)
        .exec(&db)
        .await;
    let _ = auth_service_rust::models::role::Entity::delete_by_id(&role_id)
        .exec(&db)
        .await;
}

#[tokio::test]
async fn test_login_missing_auth_record() {
    let config = AppConfig::load();
    let db = connect_db(&config).await;
    let cache = Cache::new(&config.redis_url);

    let uid: String = uuid::Uuid::new_v4().to_string().chars().take(32).collect();
    let email = format!("no-auth-{}@test.com", uid);
    let password_hash = AuthService::hash_password("test-pass").unwrap();
    let auth_id = format!("na{}", &uid[..30]);

    // Create auth record with active=false
    let auth = auth_service_rust::models::auth::ActiveModel {
        id: Set(auth_id.clone()),
        password: Set(Some(password_hash)),
        active: Set(false),
        ..Default::default()
    };
    let auth = auth.insert(&db).await.unwrap();

    let user_id = format!("nu{}", &uid[..30]);
    auth_service_rust::models::user::ActiveModel {
        id: Set(user_id.clone()),
        name: Set("Inactive Auth User".to_string()),
        email: Set(email.clone()),
        id_role: Set("administrator".to_string()),
        id_auth: Set(Some(auth.id)),
        active: Set(true),
        ..Default::default()
    }
    .insert(&db)
    .await
    .unwrap();

    // Login should fail because auth record is inactive
    let result = AuthModuleService::login(
        LoginRequest {
            email,
            password: "test-pass".to_string(),
        },
        &db,
        &cache,
        &config,
    )
    .await;
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err().message(),
        "Credenciais de acesso inativas."
    );

    delete_test_user(&db, &user_id).await;
}

#[tokio::test]
async fn test_cache_operations_error() {
    let config = AppConfig::load();
    let cache = Cache::new(&config.redis_url);
    let key = format!("test-del-{}", uuid::Uuid::new_v4());

    // Delete non-existent key should not error
    let result = cache.delete_key(&key).await;
    assert!(result.is_ok());

    // Delete invalid token session should not error
    let result = cache.delete_session("nonexistent", "invalid:token").await;
    assert!(result.is_ok());

    // Check non-existent set member
    let result = cache.is_set_member(&key, "something").await.unwrap();
    assert!(!result);
}

#[tokio::test]
async fn test_refresh_nonexistent_token() {
    let config = AppConfig::load();
    let db = connect_db(&config).await;
    let cache = Cache::new(&config.redis_url);

    // Generate a valid JWT that doesn't have a Redis session
    let (_, refresh) = AuthService::generate_tokens(
        "nonexistent-user",
        "none@test.com",
        "role",
        &config.jwt_secret,
        900,
    )
    .unwrap();

    let result = AuthModuleService::refresh(&refresh, &db, &cache, &config).await;
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().message(), "Sessão revogada ou expirada");
}

#[tokio::test]
async fn test_cache_rate_limit_error_handling() {
    let config = AppConfig::load();
    let cache = Cache::new(&config.redis_url);

    // Use a unique key
    let key = format!("rl-err-{}", uuid::Uuid::new_v4());
    let (allowed, _, _) = cache.check_rate_limit(&key, 10, 60).await.unwrap();
    assert!(allowed);
}
