# mcp-warden developer tasks. Run `make help` for the list.
.DEFAULT_GOAL := help
UV ?= uv
SCENARIO ?= all
RUN := $(UV) run

.PHONY: help setup up down logs fmt lint test test-unit test-integration test-all cov run inspector redteam bench demo demo-real demo-once soak readme-results clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

setup: ## Create the venv, install all dependency groups, install pre-commit hooks
	$(UV) sync --all-groups
	-$(RUN) pre-commit install

up: ## Start postgres, redis and jaeger in the background
	docker compose up -d --wait postgres redis jaeger

up-observability: ## Also start prometheus and grafana (dashboard on http://localhost:3000)
	docker compose up -d --wait prometheus grafana

up-all: ## Start every backing service
	docker compose up -d --wait

down: ## Stop the backing services (keeps volumes)
	docker compose down

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

readme-results: ## Regenerate the README results table from results/
	$(RUN) python -m bench.readme_results

clean: ## Remove caches, build output and local test data
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage coverage.xml dist build
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
