.PHONY: dev build test coverage check infra-up infra-stop infra-down infra-clean

# Variables
ENVIRONMENT ?= development
PORT ?= 8001

dev:
	@echo "🚀 Iniciando servidor de desenvolvimento Auth Service..."
	@if command -v cargo-watch >/dev/null 2>&1; then \
		cargo watch -c -q -x build -s "./target/debug/auth-service-rust"; \
	elif [ -f $(HOME)/.cargo/bin/cargo-watch ]; then \
		$(HOME)/.cargo/bin/cargo-watch -c -q -x build -s "./target/debug/auth-service-rust"; \
	else \
		echo "⚠️  cargo-watch não instalado. Executando diretamente..."; \
		cargo run --bin auth-service-rust; \
	fi

build:
	@echo "📦 Compilando binário de produção..."
	cargo build --release

test:
	@echo "🧪 Executando testes unitários..."
	cargo test

coverage:
	@echo "📊 Gerando relatório de cobertura..."
	cargo tarpaulin

check:
	@echo "🔍 Verificação estática..."
	cargo check

infra-up:
	@echo "🐳 Subindo infra (Postgres & Redis)..."
	docker compose -f docker-compose.infra.yml up -d

infra-stop:
	@echo "🛑 Parando infra..."
	docker compose -f docker-compose.infra.yml stop

infra-down:
	@echo "🗑️  Removendo infra..."
	docker compose -f docker-compose.infra.yml down

infra-clean:
	@echo "🧹 Limpeza completa..."
	docker compose -f docker-compose.infra.yml down -v --rmi all
