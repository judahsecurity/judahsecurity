# Judah Security ASM - Makefile
.PHONY: help build up down restart logs shell db-shell init-db clean dev dev-graph deploy \
	harness-install harness-test harness-batch harness-benchmark

# Default target
help:
	@echo "Judah Security - Attack Surface Management"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@echo "  build       Build Docker images"
	@echo "  up          Start all services"
	@echo "  down        Stop all services"
	@echo "  restart     Restart all services"
	@echo "  logs        View container logs"
	@echo "  shell       Open shell in backend container"
	@echo "  db-shell    Open PostgreSQL shell"
	@echo "  init-db     Initialize database with seed data"
	@echo "  clean       Remove containers, volumes, and images"
	@echo "  dev         Start services with development tools (Adminer)"
	@echo "  dev-graph   Start services + Neo4j graph database"
	@echo ""
	@echo "Aegis Harness (batch scanning + detection benchmarking):"
	@echo "  harness-install    Install the harness (pip install -e harness[dev])"
	@echo "  harness-test       Run the harness test suite"
	@echo "  harness-batch      Batch-scan targets in harness REPO_LIST.txt"
	@echo "  harness-benchmark  Benchmark scanner accuracy against the corpus"
	@echo ""

# Build Docker images
build:
	docker-compose build

# Start all services
up:
	docker-compose up -d
	@echo ""
	@echo "Services started!"
	@echo "  - API:     http://localhost:8000"
	@echo "  - Docs:    http://localhost:8000/api/docs"
	@echo ""

# Start with development tools
dev:
	docker-compose --profile dev up -d
	@echo ""
	@echo "Services started (development mode)!"
	@echo "  - API:      http://localhost:8000"
	@echo "  - Docs:     http://localhost:8000/api/docs"
	@echo "  - Adminer:  http://localhost:8080"
	@echo ""

# Start with development tools + Neo4j graph database
dev-graph:
	docker-compose --profile dev --profile graph up -d
	@echo ""
	@echo "Services started (development mode + Neo4j)!"
	@echo "  - API:      http://localhost:8000"
	@echo "  - Docs:     http://localhost:8000/api/docs"
	@echo "  - Adminer:  http://localhost:8080"
	@echo "  - Neo4j:    http://localhost:7474"
	@echo ""

# Stop all services
down:
	docker-compose --profile dev --profile graph down

# Restart services
restart: down up

# View logs
logs:
	docker-compose logs -f

# Open shell in backend container
shell:
	docker-compose exec backend /bin/bash

# Open PostgreSQL shell
db-shell:
	docker-compose exec db psql -U asm_user -d asm_db

# Initialize database with seed data
init-db:
	docker-compose exec backend python -m app.scripts.init_db

# Clean everything
clean:
	docker-compose --profile dev --profile graph down -v --rmi local
	@echo "Cleaned up containers, volumes, and images."

# Run tests
test:
	docker-compose exec backend pytest -v

# Show service status
status:
	docker-compose ps

# --- Aegis Harness ---------------------------------------------------------
# Batch scanning and detection-accuracy benchmarking for the Aegis Vanguard
# autonomous pentester. See harness/README.md.
harness-install:
	cd harness && pip install -e ".[dev]"

harness-test:
	cd harness && python -m pytest tests/ --cov=local_harness

harness-batch:
	cd harness && python -m local_harness.batch.run scan

harness-benchmark:
	cd harness && python -m local_harness.benchmark.run

# Deploy to EC2: make deploy EC2=1.2.3.4 KEY=~/.ssh/mykey.pem
# Only rebuilds backend + oracle; leaves db/redis/scanner untouched.
deploy:
	@[ -n "$(EC2)" ] || (echo "Usage: make deploy EC2=<ip> KEY=<path/to/key.pem>" && exit 1)
	@SSH_OPTS="-o StrictHostKeyChecking=no -i $(KEY)"; \
	echo "→ Deploying to ubuntu@$(EC2):/opt/asm"; \
	ssh $$SSH_OPTS ubuntu@$(EC2) '\
	  cd /opt/asm && \
	  git pull && \
	  docker compose build backend aegis-oracle && \
	  docker compose up -d --no-deps backend aegis-oracle frontend && \
	  docker exec asm_backend python scripts/migrate_add_oracle_columns.py --backfill 2>/dev/null || true && \
	  echo "" && echo "✓ Done." && docker compose ps'

















