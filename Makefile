# mcp-warden developer tasks. Run `make help` for the list.
.DEFAULT_GOAL := help
UV ?= uv
SCENARIO ?= all
RUN := $(UV) run

.PHONY: security help setup up down logs fmt lint test test-unit test-integration test-all cov run inspector redteam bench demo demo-real demo-once soak readme-results image image-ml image-sizes clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

setup: ## Create the venv, install all dependency groups, install pre-commit hooks
	$(UV) sync --all-groups
	-$(RUN) pre-commit install

up: ## Start postgres, redis and jaeger in the background
	docker compose up -d --wait postgres redis jaeger

up-observability: ## Also start prometheus and grafana (dashboard on http://localhost:3000)
	docker compose up -d --wait prometheus grafana

up-all: ## The whole stack in containers: gateway (+ its upstreams), postgres, redis, jaeger, prometheus, grafana
	PROMETHEUS_CONFIG=prometheus.container.yml docker compose --profile gateway up -d --wait --build
	@echo "gateway   http://localhost:8080/mcp   (mint a key: docker compose exec gateway warden keys create --user you --roles editor)"
	@echo "approvals http://localhost:8080/approvals"
	@echo "jaeger    http://localhost:16686   grafana http://localhost:3000   prometheus http://localhost:9090"

down: ## Stop everything, including a containerised gateway (keeps volumes)
	docker compose --profile gateway down

logs: ## Tail the backing-service logs
	docker compose logs -f

fmt: ## Format the code with ruff
	$(RUN) ruff format .
	$(RUN) ruff check --fix .

lint: ## Lint (ruff) and type-check (mypy --strict on src/warden)
	$(RUN) ruff check .
	$(RUN) ruff format --check .
	$(RUN) mypy src/warden servers

test: ## Run unit + integration tests
	$(RUN) pytest -m "unit or integration" -q

test-unit: ## Run unit tests only (no docker, no network)
	$(RUN) pytest -m unit -q

test-integration: ## Run integration tests only
	$(RUN) pytest -m integration -q

test-all: ## Run every test layer, including e2e, ml, redteam and perf
	$(RUN) pytest -q

cov: ## Run unit + integration tests with the coverage gate on src/warden
	$(RUN) pytest -m "unit or integration" --cov=src/warden --cov-report=term-missing --cov-report=xml --cov-fail-under=85

run: ## Run the gateway on $$WARDEN_PORT (default 8080)
	$(RUN) warden serve

inspector: ## Launch the MCP Inspector web UI (add the gateway + header in the UI; see docs/clients.md)
	npx -y @modelcontextprotocol/inspector

security: ## Static analysis (bandit) and a known-vulnerability audit of the locked dependencies
	$(RUN) bandit -r src/warden servers -q
	$(UV) export --frozen --all-groups --all-extras --no-emit-project --format requirements-txt > .audit-requirements.txt
	$(RUN) pip-audit -r .audit-requirements.txt --disable-pip --no-deps --progress-spinner off
	@rm -f .audit-requirements.txt

redteam: ## Run the red-team suite (both configurations) and write results/
	$(RUN) python -m redteam.runner

redteam-rules: ## Run the red-team suite rules-only, as CI does
	$(RUN) python -m redteam.runner --rules-only

bench: ## Run the latency benchmark and write results/
	$(RUN) python -m bench.latency

demo: ## Run the demo scenarios with the scripted model and write results/: make demo SCENARIO=benign
	$(RUN) python -m agent.runner --scenario $(SCENARIO)

demo-real: ## Same, driven by a local Ollama model (needs `ollama pull $$OLLAMA_MODEL`)
	$(RUN) python -m agent.runner --scenario $(SCENARIO) --real-model

demo-once: ## One scenario, one run, printed step by step rather than written to results/
	$(RUN) python -m agent.demo_agent --scenario $(SCENARIO)

soak: ## Run the 30-minute soak test and write results/
	$(RUN) python -m bench.soak

image: ## Build the rules-only gateway image (mcp-warden:local)
	docker build -t mcp-warden:local .

image-ml: ## Build the image with the local classifier (mcp-warden:ml)
	docker build --build-arg WITH_ML=true -t mcp-warden:ml .

image-sizes: ## Record the built image sizes into results/
	$(RUN) python -m bench.image_sizes

readme-results: ## Regenerate the README results table from results/
	$(RUN) python -m bench.readme_results

clean: ## Remove caches, build output and local test data
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage coverage.xml dist build
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
