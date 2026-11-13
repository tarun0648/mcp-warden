# mcp-warden developer tasks. Run `make help` for the list.
.DEFAULT_GOAL := help
UV ?= uv
RUN := $(UV) run

.PHONY: help setup up down logs fmt lint test test-unit test-integration test-all cov run inspector redteam bench demo soak readme-results clean

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

setup: ## Create the venv, install all dependency groups, install pre-commit hooks
	$(UV) sync --all-groups
	-$(RUN) pre-commit install

up: ## Start postgres, redis and jaeger in the background
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

inspector: ## Launch the MCP Inspector against the running gateway
	npx @modelcontextprotocol/inspector

redteam: ## Run the red-team suite and write results/
	$(RUN) python -m redteam.runner

bench: ## Run the latency benchmark and write results/
	$(RUN) python -m bench.latency

demo: ## Run one Ollama demo scenario: make demo SCENARIO=benign
	$(RUN) python -m agent.demo_agent --scenario $(SCENARIO)

soak: ## Run the 30-minute soak test and write results/
	$(RUN) python -m bench.soak

readme-results: ## Regenerate the README results table from results/
	$(RUN) python -m bench.readme_results

clean: ## Remove caches, build output and local test data
	rm -rf .pytest_cache .mypy_cache .ruff_cache htmlcov .coverage coverage.xml dist build
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
