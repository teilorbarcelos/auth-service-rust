use crate::{
    config::TableNames,
    models::{auth, role, role_feature, user},
};
use sea_orm::{
    sea_query::Value,
    ConnectionTrait, DatabaseConnection, DbErr, FromQueryResult, Statement,
};

async fn query_one<M>(db: &DatabaseConnection, sql: String, values: Vec<Value>) -> Result<Option<M>, DbErr>
where
    M: FromQueryResult + Send + Sync + 'static,
{
    let backend = db.get_database_backend();
    let stmt = Statement::from_sql_and_values(backend, sql, values);
    let row = db.query_one(stmt).await?;
    match row {
        Some(row) => Ok(Some(M::from_query_result(&row, "")?)),
        None => Ok(None),
    }
}

async fn query_all<M>(db: &DatabaseConnection, sql: String, values: Vec<Value>) -> Result<Vec<M>, DbErr>
where
    M: FromQueryResult + Send + Sync + 'static,
{
    let backend = db.get_database_backend();
    let stmt = Statement::from_sql_and_values(backend, sql, values);
    let rows = db.query_all(stmt).await?;
    rows.into_iter()
        .map(|row| M::from_query_result(&row, ""))
        .collect()
}

pub async fn find_user_by_email(
    db: &DatabaseConnection,
    tn: &TableNames,
    email: &str,
) -> Result<Option<user::Model>, DbErr> {
    let sql = format!(
        r#"SELECT * FROM "{}" WHERE email = $1 AND ("is_deleted" IS NULL OR "is_deleted" = false) LIMIT 1"#,
        tn.user
    );
    query_one(db, sql, vec![email.into()]).await
}

pub async fn find_user_by_id(
    db: &DatabaseConnection,
    tn: &TableNames,
    id: &str,
) -> Result<Option<user::Model>, DbErr> {
    let sql = format!(
        r#"SELECT * FROM "{}" WHERE id = $1 LIMIT 1"#,
        tn.user
    );
    query_one(db, sql, vec![id.into()]).await
}

pub async fn find_role_by_id(
    db: &DatabaseConnection,
    tn: &TableNames,
    id: &str,
) -> Result<Option<role::Model>, DbErr> {
    let sql = format!(
        r#"SELECT * FROM "{}" WHERE id = $1 AND ("is_deleted" IS NULL OR "is_deleted" = false) LIMIT 1"#,
        tn.role
    );
    query_one(db, sql, vec![id.into()]).await
}

pub async fn find_auth_by_id(
    db: &DatabaseConnection,
    tn: &TableNames,
    id: &str,
) -> Result<Option<auth::Model>, DbErr> {
    let sql = format!(
        r#"SELECT * FROM "{}" WHERE id = $1 LIMIT 1"#,
        tn.auth
    );
    query_one(db, sql, vec![id.into()]).await
}

pub async fn find_permissions_by_role(
    db: &DatabaseConnection,
    tn: &TableNames,
    role_id: &str,
) -> Result<Vec<role_feature::Model>, DbErr> {
    let sql = format!(
        r#"SELECT * FROM "{}" WHERE id_role = $1"#,
        tn.role_feature
    );
    query_all(db, sql, vec![role_id.into()]).await
}
