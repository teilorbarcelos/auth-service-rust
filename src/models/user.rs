use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(schema_name = "public", table_name = "User")]
pub struct Model {
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: String,
    pub name: String,
    pub phone: Option<String>,
    pub email: String,
    pub cognito_id: Option<String>,
    pub active: bool,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
    pub document: Option<String>,
    pub is_deleted: Option<bool>,
    pub deleted_at: Option<DateTimeWithTimeZone>,
    pub avatar: Option<String>,
    pub id_auth: Option<String>,
    pub id_role: String,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::auth::Entity",
        from = "Column::IdAuth",
        to = "super::auth::Column::Id",
        on_update = "Cascade",
        on_delete = "SetNull"
    )]
    Auth,
    #[sea_orm(
        belongs_to = "super::role::Entity",
        from = "Column::IdRole",
        to = "super::role::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Role,
}

impl Related<super::auth::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Auth.def()
    }
}

impl Related<super::role::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Role.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
