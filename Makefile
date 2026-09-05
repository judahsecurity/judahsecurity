# Judah Security ASM - Makefile
.PHONY: help build up down restart logs shell db-shell init-db clean dev dev-graph deploy \
	harness-install harness-test harness-batch harness-benchmark \
	agent-run agent-playbooks agent-status agent-benchmark agent-benchmark-baseline \
	agent-subscription

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
	@echo "Aegis Agent (headless console engagements):"
	@echo "  agent-status       Check whether an LLM runtime is configured"
	@echo "  agent-playbooks    List available playbooks"
	@echo "  agent-run          Start an engagement:"
	@echo "                       make agent-run TARGET=https://app.example.com"
	@echo "                       make agent-run TARGET=<url> PLAYBOOK=tester_process"
	@echo "                       make agent-run TARGET=<url> QUESTION=\"find IDORs\" MODE=agent ORG=1"
	@echo "  agent-benchmark    Benchmark the in-product agent (Glasswing contract) on the corpus"
	@echo "  agent-benchmark-baseline  Same, but with the verify/coverage gate disabled (baseline)"
	@echo "  agent-subscription Run Vanguard via Claude Agent SDK on a Pro/Max subscription:"
	@echo "                       make agent-subscription TARGET=https://example.com"
	@echo "                       Needs Docker running + an LLM key + backend deps importable."
	@echo "                       make agent-benchmark ARGS=\"--repos juice-shop --setup\""
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

# --- Aegis Agent (headless console) ----------------------------------------
# Kick off an engagement without the HTTP layer, reusing the same
# AgentOrchestrator.invoke() path as the API. See backend/app/cli.py.
agent-status:
	docker-compose exec backend python -m app.cli status

agent-playbooks:
	docker-compose exec backend python -m app.cli playbooks

# make agent-run TARGET=<url> [PLAYBOOK=<id>] [QUESTION="..."] [MODE=agent|assist] [ORG=<n>]
agent-run:
	@[ -n "$(TARGET)$(QUESTION)$(PLAYBOOK)" ] || (echo 'Usage: make agent-run TARGET=<url> [PLAYBOOK=<id>] [QUESTION="..."] [MODE=agent|assist] [ORG=<n>]' && exit 1)
	docker-compose exec backend python -m app.cli run \
	  $(if $(TARGET),--target "$(TARGET)") \
	  $(if $(PLAYBOOK),--playbook "$(PLAYBOOK)") \
	  $(if $(QUESTION),--question "$(QUESTION)") \
	  $(if $(MODE),--mode "$(MODE)") \
	  $(if $(ORG),--org "$(ORG)")

# Benchmark the IN-PRODUCT agent (engagement brain + independent verifier +
# coverage) against the known-vulnerable corpus, by pointing the harness scanner
# command at the CLI. The agent mirrors findings to AEGIS_FINDINGS_SINK (set by
# the harness) so the judge can score them. Prereqs: Docker running (for --setup
# targets), an LLM key in the environment, and backend deps importable.
#   make agent-benchmark ARGS="--repos juice-shop --setup"
AGENT_PY ?= backend/.venv311/bin/python
agent-benchmark:
	cd harness && \
	  AEGIS_HARNESS_SCANNER_CMD="$(abspath $(AGENT_PY)) -m app.cli run" \
	  AEGIS_HARNESS_SCANNER_CWD="$(abspath backend)" \
	  PYTHONPATH=. "$(abspath $(AGENT_PY))" -m local_harness.benchmark.run $(ARGS)

# Same run with the Glasswing verify/coverage gate DISABLED — the baseline half
# of the with/without-contract comparison.
agent-benchmark-baseline:
	cd harness && \
	  AEGIS_DISABLE_VERIFY_GATE=1 \
	  AEGIS_HARNESS_SCANNER_CMD="$(abspath $(AGENT_PY)) -m app.cli run" \
	  AEGIS_HARNESS_SCANNER_CWD="$(abspath backend)" \
	  PYTHONPATH=. "$(abspath $(AGENT_PY))" -m local_harness.benchmark.run $(ARGS)

# Run Vanguard through the Claude Agent SDK, billed to a Claude Pro/Max
# subscription (CLAUDE_CODE_OAUTH_TOKEN). Personal/research use only — see
# aegis-claude-sdk/README.md for the Terms-of-Service caveat. Runs on the host
# (needs the `claude` CLI + Python deps), not in Docker.
#   make agent-subscription TARGET=https://example.com [SCOPE=example.com] [ARGS="--max-risk medium"]
SUBSCRIPTION_PY ?= python3
agent-subscription:
	@[ -n "$(TARGET)" ] || (echo 'Usage: make agent-subscription TARGET=<url> [SCOPE=<domain>] [ARGS="..."]' && exit 1)
	cd aegis-claude-sdk && "$(SUBSCRIPTION_PY)" pentest_subscription.py \
	  --target "$(TARGET)" \
	  $(if $(SCOPE),--scope "$(SCOPE)") \
	  $(ARGS)

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

# Deploy Vanguard agent changes to EC2: make deploy-vanguard EC2=1.2.3.4 KEY=~/.ssh/mykey.pem
# The scanner worker runs `docker run aegis-vanguard:latest` (Dockerfile.scanner),
# and `make deploy` does NOT rebuild that image — so Vanguard code changes only go
# live after this target rebuilds aegis-vanguard:latest on the host.
deploy-vanguard:
	@[ -n "$(EC2)" ] || (echo "Usage: make deploy-vanguard EC2=<ip> KEY=<path/to/key.pem>" && exit 1)
	@SSH_OPTS="-o StrictHostKeyChecking=no -i $(KEY)"; \
	echo "→ Rebuilding aegis-vanguard:latest on ubuntu@$(EC2):/opt/asm"; \
	ssh $$SSH_OPTS ubuntu@$(EC2) '\
	  cd /opt/asm && \
	  git pull && \
	  docker build -t aegis-vanguard:latest -f aegis-vanguard/Dockerfile . && \
	  echo "" && echo "✓ aegis-vanguard:latest rebuilt — the scanner worker will use it on the next run." && \
	  docker image inspect aegis-vanguard:latest --format "  built: {{.Created}}  id: {{.Id}}"'

















