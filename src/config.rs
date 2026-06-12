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
        }
    }
}
