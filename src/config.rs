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
    pub table_naming: TableNaming,
    pub manage_sessions: bool,
}

#[derive(Clone, Debug)]
pub enum TableNaming {
    Pascal,
    Lower,
}

#[derive(Clone, Debug)]
pub struct TableNames {
    pub user: &'static str,
    pub auth: &'static str,
    pub role: &'static str,
    pub feature: &'static str,
    pub role_feature: &'static str,
}

impl TableNaming {
    pub fn tables(&self) -> TableNames {
        match self {
            TableNaming::Pascal => TableNames {
                user: "User",
                auth: "Auth",
                role: "Role",
                feature: "Feature",
                role_feature: "RoleFeature",
            },
            TableNaming::Lower => TableNames {
                user: "user",
                auth: "auth",
                role: "role",
                feature: "feature",
                role_feature: "role_feature",
            },
        }
    }
}

#[derive(Clone, Debug)]
pub struct RedisKeys {
    pub session_version: &'static str,
    pub session_token: &'static str,
    pub permissions: &'static str,
}

impl RedisKeys {
    pub fn for_naming(naming: &TableNaming) -> Self {
        match naming {
            TableNaming::Pascal => Self {
                session_version: "session:user:{}:version",
                session_token: "session:user:{}:token:{}",
                permissions: "session:{}:permissions",
            },
            TableNaming::Lower => Self {
                session_version: "session:ver:{}",
                session_token: "session:role:{}:user:{}:access:{}",
                permissions: "session:{}:permissions",
            },
        }
    }
}

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

        let naming_raw = env::var("DB_TABLE_NAMING").unwrap_or_else(|_| "pascal".to_string());
        let table_naming = match naming_raw.to_lowercase().as_str() {
            "lower" | "snake" => TableNaming::Lower,
            _ => TableNaming::Pascal,
        };

        let manage_sessions = env::var("MANAGE_SESSIONS")
            .unwrap_or_else(|_| "true".to_string())
            .parse::<bool>()
            .unwrap_or(true);

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
            table_naming,
            manage_sessions,
        }
    }
}
