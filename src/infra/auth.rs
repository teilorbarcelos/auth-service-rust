use crate::{config::BackendProfile, errors::AppError};
use bcrypt::{hash, verify};
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const BCRYPT_COST: u32 = 12;

/// Claims fixos que todo JWT contém (decodificação universal).
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub email: String,
    pub role: String,
    pub exp: i64,
    pub iat: i64,
}

pub struct AuthService;

impl AuthService {
    pub fn hash_password(password: &str) -> Result<String, AppError> {
        let hashed = hash(password, BCRYPT_COST)
            .map_err(|e| AppError::Internal(format!("Falha ao criptografar senha: {}", e)))?;
        Ok(hashed)
    }

    pub fn verify_password(password: &str, hash: &str) -> Result<bool, AppError> {
        let matches = verify(password, hash)
            .map_err(|e| AppError::Internal(format!("Falha ao verificar senha: {}", e)))?;
        Ok(matches)
    }

    pub fn generate_tokens(
        user_id: &str,
        email: &str,
        role: &str,
        secret: &str,
        expires_sec: i64,
        session_version: i64,
        permissions: &[crate::modules::auth::schemas::PermissionInfo],
        profile: &BackendProfile,
    ) -> Result<(String, String), AppError> {
        let now = Utc::now();
        let iat = now.timestamp();
        let exp = now + Duration::seconds(expires_sec);

        let access_token = Self::build_token(
            user_id, email, role, secret, exp.timestamp(), iat,
            session_version, permissions, profile, false,
        )?;

        let refresh_exp = now + Duration::seconds(7 * 24 * 60 * 60);
        let refresh_token = Self::build_token(
            user_id, email, role, secret, refresh_exp.timestamp(), iat,
            session_version, &[], profile, true,
        )?;

        Ok((access_token, refresh_token))
    }

    fn build_token(
        user_id: &str,
        email: &str,
        role: &str,
        secret: &str,
        exp: i64,
        iat: i64,
        session_version: i64,
        permissions: &[crate::modules::auth::schemas::PermissionInfo],
        profile: &BackendProfile,
        is_refresh: bool,
    ) -> Result<String, AppError> {
        let mut claims: HashMap<String, serde_json::Value> = HashMap::new();

        // Claims universais (sempre presentes, usados pelo auth-service internamente)
        claims.insert("sub".to_string(), serde_json::Value::String(user_id.to_string()));
        claims.insert("email".to_string(), serde_json::Value::String(email.to_string()));
        claims.insert("role".to_string(), serde_json::Value::String(role.to_string()));
        claims.insert("exp".to_string(), serde_json::Value::Number(serde_json::Number::from(exp)));
        claims.insert("iat".to_string(), serde_json::Value::Number(serde_json::Number::from(iat)));

        // ID field específico do backend (sub | id | uid)
        if profile.jwt_id_field != "sub" {
            claims.insert(
                profile.jwt_id_field.to_string(),
                serde_json::Value::String(user_id.to_string()),
            );
        }

        // Role field específico do backend (role | roleId)
        if profile.jwt_role_field != "role" {
            claims.insert(
                profile.jwt_role_field.to_string(),
                serde_json::Value::String(role.to_string()),
            );
        }

        if !is_refresh {
            // Session version (opcional)
            if let Some(sv_field) = profile.jwt_session_field {
                claims.insert(sv_field.to_string(), serde_json::json!(session_version));
            }

            // Permissions (opcional)
            if profile.jwt_include_permissions {
                let perms: Vec<serde_json::Value> = permissions
                    .iter()
                    .map(|p| {
                        serde_json::json!({
                            "feature": p.feature,
                            "create": p.create,
                            "view": p.view,
                            "activate": p.activate,
                            "delete": p.delete,
                        })
                    })
                    .collect();
                claims.insert("permissions".to_string(), serde_json::Value::Array(perms));
            }

            // JTI (opcional, usado por Python e C#)
            if profile.jwt_include_jti {
                claims.insert(
                    "jti".to_string(),
                    serde_json::Value::String(uuid::Uuid::new_v4().to_string()),
                );
            }
        }

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .map_err(|e| AppError::Internal(format!("Erro ao assinar JWT: {}", e)))
    }

    pub fn verify_token(token: &str, secret: &str) -> Result<Claims, AppError> {
        let validation = Validation::default();
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(secret.as_bytes()),
            &validation,
        )?;
        Ok(token_data.claims)
    }
}
