# Auth Service (Rust) 🔐

Microsserviço de autenticação dedicado, extraído do `backend-rust`.
Alta performance, mínimo acoplamento, **plug-and-play** com o monólito.

---

## 🚀 Tecnologias

- **Runtime:** [Tokio](https://tokio.rs/)
- **Framework Web:** [Axum](https://github.com/tokio-rs/axum)
- **ORM:** [Sea-ORM](https://www.sea-ql.org/)
- **Database:** PostgreSQL (leitura) & Redis (sessão + cache)
- **Autenticação:** JWT (HS256) + bcrypt
- **Linter & Formatter:** Clippy & Rustfmt

---

## ✨ Funcionalidades

- **Login / Refresh / Logout** via JWT com refresh token rotation
- **RBAC no Redis:** Permissões cacheadas em `session:{user_id}:permissions` (TTL 1h)
- **Session Epoch:** Invalidação O(1) de todas as sessões de um usuário
- **Rate Limiting:** Script Lua atômico no Redis
- **Health Checks:** `/health`, `/liveness`, `/ready`
- **JWKS Endpoint:** `GET /v1/auth/.well-known/jwks.json` (placeholder para RS256)
- **Request Logging:** Log estruturado com method, path, status e duração

---

## 🔌 Plug-and-Play: Monolito → Microsserviço

O `auth-service-rust` foi projetado para substituir o módulo de autenticação do `backend-rust` sem alterar o middleware, o RBAC ou a sessão Redis.

### Como funciona

```
FRONTEND                   AUTH SERVICE (8001)         MONOLITH (8888)
   │                            │                          │
   ├─ POST /login ────────────→│                          │
   │                            ├─ SELECT User+Auth+Role  │
   │                            ├─ bcrypt verify          │
   │                            ├─ Redis: create session  │
   │                            ├─ JWT (HS256)            │
   │←── { token, refresh } ────│                          │
   │                                                      │
   ├─ GET /orders (JWT) ────────────────────────────────→│
   │                                                      │
   │                          ├─ valida JWT local (HS256) │
   │                          ├─ lê permissions do Redis  │
   │                          ├─ RBAC check (SEM DB)      │
   │←─────────────────────────────────────────────────────│
```

### Modos de operação

#### Modo Monolítico (default)

O `backend-rust` gerencia tudo — auth incluso. **Nenhuma configuração extra.**

```bash
AUTH_MODE=local    # (default) autenticação no próprio monólito
```

#### Modo Microsserviço (opt-in)

Auth extraído para o `auth-service-rust`. O monólito mantém validação JWT + RBAC.

```bash
# backend-rust/.env
AUTH_MODE=remote   # desliga /v1/auth/* no monólito

# auth-service-rust/.env
BACKEND_TARGET=rust
JWT_SECRET=<mesma do monólito>
DATABASE_URL=<mesma do monólito>
REDIS_URL=<mesma do monólito>
```

### Passo a passo

```bash
# 1. Clone e configure o auth-service
cd auth-service-rust
cp .env.example .env
# Edite .env: mesma DATABASE_URL, JWT_SECRET e REDIS_URL do monólito

# 2. Suba o auth-service (porta 8001)
make dev

# 3. No monólito, ative o modo remoto
# backend-rust/.env → AUTH_MODE=remote

# 4. Frontend passa a chamar:
#   - POST /v1/auth/login        → auth-service (8001)
#   - POST /v1/auth/refresh      → auth-service (8001)
#   - POST /v1/auth/logout       → auth-service (8001)
#   - Demais endpoints           → monólito (8888)

# 5. Pronto! O JWT emitido pelo auth-service é aceito pelo monólito.
```

### O que muda no monólito

| Componente | Antes (monolito) | Depois (auth-service) |
|---|---|---|
| `POST /v1/auth/login` | Handler local | ❌ Remove |
| `POST /v1/auth/refresh` | Handler local | ❌ Remove |
| `POST /v1/auth/logout` | Handler local | ❌ Remove |
| Middleware JWT | `verify_token(token, secret)` | ✅ **Igual** |
| Middleware RBAC | Lê Redis `session:{id}:permissions` | ✅ **Igual** |
| Session version | `cache.validate_session()` | ✅ **Igual** |

> **Apenas 3 handlers são removidos.** Todo o resto (middleware, RBAC, Redis) continua inalterado.

---

## 🏁 Começando

### Pré-requisitos

- Rust 1.83+
- Docker (PostgreSQL + Redis)
- `backend-rust` rodando (para criar as tabelas)

### Setup

```bash
# 1. Suba infraestrutura
make infra-up

# 2. Configure o ambiente
cp .env.example .env
# Edite DATABASE_URL, JWT_SECRET e REDIS_URL

# 3. Inicie o servidor
make dev
```

### Variáveis de ambiente

```bash
ENVIRONMENT=local
PORT=8001                   # Porta do auth-service
HOST=0.0.0.0

DATABASE_URL=postgresql://postgres:postgrespw@localhost:5432/backend_rust?schema=public
REDIS_URL=redis://127.0.0.1:6379

JWT_SECRET=super-secret-key-change-me
JWT_EXPIRES_IN=900          # 15 min
JWT_REFRESH_EXPIRES_IN=604800  # 7 dias

CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
```

---

## 📡 Endpoints

| Método | Rota | Auth | Descrição |
|--------|------|------|-----------|
| POST | `/v1/auth/login` | ❌ | Login (email + password) |
| POST | `/v1/auth/refresh` | ❌ | Renova par de tokens |
| POST | `/v1/auth/logout` | ✅ | Revoga sessão |
| GET | `/v1/auth/me` | ✅ | Dados do usuário logado |
| GET | `/v1/auth/.well-known/jwks.json` | ❌ | JWKS (placeholder RS256) |
| GET | `/health` | ❌ | Health check |
| GET | `/liveness` | ❌ | Liveness probe |
| GET | `/ready` | ❌ | Readiness probe |

---

## 🧪 Testes

```bash
# Testes unitários e de integração
cargo test

# Cobertura
cargo tarpaulin

# Linter
cargo clippy --all-targets -- -D warnings

# Formatação
cargo fmt --check
```

### Compliance (E2E com monólito)

```bash
cd ../mage-backend-compliance

# Modo monolítico (auth no monólito)
cp .env.rust .env
make test-rust

# Modo microsserviço (auth no auth-service)
cp .env.auth.rust .env
make test-auth-rust
```

---

## 📊 Qualidade

- **58 testes** (13 unit + 24 integration + 21 HTTP)
- **~96% de cobertura**
- **SonarQube:** Quality Gate A (0 bugs, 0 vulnerabilidades, 0 code smells)
- **Clippy:** 0 warnings
- **Rustfmt:** formatação padronizada
