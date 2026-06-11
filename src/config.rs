use std::env;

#[derive(Clone, Debug)]
pub struct AppConfig {
    pub port: u16,
    pub host: String,
    pub database_url: String,
    pub redis_url: String,
    pub jwt_secret: String,
    pub jwt_expires_in: i64,
    pub jwt_refresh_expires_in: i64,
    pub environment: String,
    pub debug: bool,
    pub cors_allowed_origins: String,
    pub profile: BackendProfile,
}

/// Perfil completo de um backend-alvo: define nomes de tabelas, chaves Redis,
/// formato dos claims JWT e comportamento de sessão.
#[derive(Clone, Debug)]
pub struct BackendProfile {
    pub name: &'static str,

    // ── Nomes de tabelas ──────────────────────────────────────
    pub table_user: &'static str,
    pub table_auth: &'static str,
    pub table_role: &'static str,
    pub table_feature: &'static str,
    pub table_role_feature: &'static str,

    // ── Chaves Redis (placeholders: {user_id}, {role_id}, {token}) ──
    pub redis_session_version: &'static str,
    pub redis_token_key: &'static str,
    pub redis_permissions: &'static str,

    // ── Nomes dos claims JWT ───────────────────────────────────
    pub jwt_id_field: &'static str,        // "sub" | "id" | "uid"
    pub jwt_role_field: &'static str,      // "role" | "roleId"
    pub jwt_session_field: Option<&'static str>, // None | "sessionVersion" | "sv" | "ver"
    pub jwt_include_permissions: bool,
    pub jwt_include_jti: bool,

    // ── Gerenciamento de sessão ────────────────────────────────
    pub manage_sessions: bool,
}

impl BackendProfile {
    pub fn for_target(target: &str) -> Self {
        match target.to_lowercase().as_str() {
            "rust" | "backend-rust" => PROFILES.rust.clone(),
            "go" | "golang" | "backend-go" => PROFILES.go.clone(),
            "node" | "nodejs" | "backend-node" => PROFILES.node.clone(),
            "python" | "backend-python" => PROFILES.python.clone(),
            "csharp" | "c-sharp" | "backend-c-sharp" => PROFILES.csharp.clone(),
            "php" | "slim" | "backend-php-slim" => PROFILES.php.clone(),
            "java" | "quarkus" | "backend-java-quarkus" => PROFILES.java.clone(),
            _ => {
                tracing::warn!(
                    "BACKEND_TARGET '{}' desconhecido. Usando perfil Rust (padrão).",
                    target
                );
                PROFILES.rust.clone()
            }
        }
    }
}

struct Profiles {
    rust: BackendProfile,
    go: BackendProfile,
    node: BackendProfile,
    python: BackendProfile,
    csharp: BackendProfile,
    php: BackendProfile,
    java: BackendProfile,
}

static PROFILES: Profiles = Profiles {
    // ── Rust (backend-rust) ────────────────────────────────────
    rust: BackendProfile {
        name: "rust",
        table_user: "User",
        table_auth: "Auth",
        table_role: "Role",
        table_feature: "Feature",
        table_role_feature: "RoleFeature",
        redis_session_version: "session:user:{}:version",
        redis_token_key: "session:user:{}:token:{}",
        redis_permissions: "session:{}:permissions",
        jwt_id_field: "sub",
        jwt_role_field: "role",
        jwt_session_field: None,
        jwt_include_permissions: false,
        jwt_include_jti: false,
        manage_sessions: true,
    },

    // ── Go (backend-go) ────────────────────────────────────────
    go: BackendProfile {
        name: "go",
        table_user: "user",
        table_auth: "auth",
        table_role: "role",
        table_feature: "feature",
        table_role_feature: "role_feature",
        redis_session_version: "session:ver:{}",
        redis_token_key: "session:role:{role_id}:user:{user_id}:access:{token}",
        redis_permissions: "session:{}:permissions",
        jwt_id_field: "id",
        jwt_role_field: "roleId",
        jwt_session_field: Some("sessionVersion"),
        jwt_include_permissions: true,
        jwt_include_jti: false,
        manage_sessions: true,
    },

    // ── Node (backend-node) ────────────────────────────────────
    node: BackendProfile {
        name: "node",
        table_user: "User",
        table_auth: "Auth",
        table_role: "Role",
        table_feature: "Feature",
        table_role_feature: "RoleFeature",
        redis_session_version: "session:user:{}:version",
        redis_token_key: "session:user:{}:token:{}",
        redis_permissions: "session:{}:permissions",
        jwt_id_field: "id",
        jwt_role_field: "roleId",
        jwt_session_field: None,
        jwt_include_permissions: true,
        jwt_include_jti: false,
        manage_sessions: false,
    },

    // ── Python (backend-python) ────────────────────────────────
    python: BackendProfile {
        name: "python",
        table_user: "user",
        table_auth: "auth",
        table_role: "role",
        table_feature: "feature",
        table_role_feature: "role_feature",
        redis_session_version: "user:session_version:{}",
        redis_token_key: "user:sessions:{}",
        redis_permissions: "user:permissions:{}",
        jwt_id_field: "id",
        jwt_role_field: "roleId",
        jwt_session_field: Some("ver"),
        jwt_include_permissions: true,
        jwt_include_jti: true,
        manage_sessions: false,
    },

    // ── C# (backend-c-sharp) ───────────────────────────────────
    csharp: BackendProfile {
        name: "csharp",
        table_user: "User",
        table_auth: "Auth",
        table_role: "Role",
        table_feature: "Feature",
        table_role_feature: "RoleFeature",
        redis_session_version: "session:user:{}:version",
        redis_token_key: "session:user:{}:token:{}",
        redis_permissions: "session:{}:permissions",
        jwt_id_field: "id",
        jwt_role_field: "roleId",
        jwt_session_field: Some("sv"),
        jwt_include_permissions: true,
        jwt_include_jti: true,
        manage_sessions: false,
    },

    // ── PHP Slim (backend-php-slim) ────────────────────────────
    php: BackendProfile {
        name: "php",
        table_user: "users",
        table_auth: "auth",
        table_role: "roles",
        table_feature: "features",
        table_role_feature: "role_features",
        redis_session_version: "user:session_version:{}",
        redis_token_key: "user:sessions:{}",
        redis_permissions: "user:permissions:{}",
        jwt_id_field: "uid",
        jwt_role_field: "roleId",
        jwt_session_field: Some("sv"),
        jwt_include_permissions: true,
        jwt_include_jti: false,
        manage_sessions: false,
    },

    // ── Java Quarkus (backend-java-quarkus) ────────────────────
    java: BackendProfile {
        name: "java",
        table_user: "users",
        table_auth: "auth",
        table_role: "roles",
        table_feature: "features",
        table_role_feature: "role_features",
        redis_session_version: "session:user:{}",
        redis_token_key: "session:user:{}:token:{}",
        redis_permissions: "session:{}:permissions",
        jwt_id_field: "uid",
        jwt_role_field: "roleId",
        jwt_session_field: Some("sv"),
        jwt_include_permissions: true,
        jwt_include_jti: false,
        manage_sessions: false,
    },
};

impl AppConfig {
    pub fn load() -> Self {
        let _ = dotenvy::dotenv();

        let port = env::var("PORT")
            .unwrap_or_else(|_| "8001".to_string())
            .parse::<u16>()
            .expect("PORT must be a valid number");

        let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());

        let database_url = env::var("DATABASE_URL").unwrap_or_else(|_| {
            format!(
                "postgresql://{}:{}@localhost:5432/backend_rust?schema=public",
                "postgres", "postgrespw"
            )
        });

        let redis_url =
            env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());

        let jwt_secret = env::var("JWT_SECRET")
            .unwrap_or_else(|_| format!("{}-{}", "super-secret-key", "change-me"));

        let jwt_expires_in = env::var("JWT_EXPIRES_IN")
            .unwrap_or_else(|_| "900".to_string())
            .parse::<i64>()
            .unwrap_or(900);

        let jwt_refresh_expires_in = env::var("JWT_REFRESH_EXPIRES_IN")
            .unwrap_or_else(|_| "604800".to_string())
            .parse::<i64>()
            .unwrap_or(604800);

        let environment = env::var("ENVIRONMENT").unwrap_or_else(|_| "development".to_string());
        let debug = env::var("DEBUG")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .unwrap_or(true);

        let cors_allowed_origins =
            env::var("CORS_ALLOWED_ORIGINS").unwrap_or_else(|_| "".to_string());

        let target = env::var("BACKEND_TARGET").unwrap_or_else(|_| "rust".to_string());
        let profile = BackendProfile::for_target(&target);

        tracing::info!(
            "Perfil carregado: {} (manage_sessions={}, jwt_id={})",
            profile.name,
            profile.manage_sessions,
            profile.jwt_id_field,
        );

        Self {
            port,
            host,
            database_url,
            redis_url,
            jwt_secret,
            jwt_expires_in,
            jwt_refresh_expires_in,
            environment,
            debug,
            cors_allowed_origins,
            profile,
        }
    }
}
