.PHONY: test cov run ablate serve \
        stack-up stack-run stack-web stack-ps stack-logs stack-down stack-clean clean

# --- local (uv) --------------------------------------------------------------
test:
	uv run pytest

cov:
	uv run pytest --cov=orchestrator --cov-report=term-missing

run:
	uv run security-orchestrator run --out runs/latest --save-policy runs/latest/hardened.yaml

ablate:
	uv run security-orchestrator ablate --out runs/ablation

serve:
	uv run --extra web security-orchestrator serve

# --- the Docker stack (real OpenShell gateway + our code) --------------------
# Prereq: copy .env.example to .env and fill in the real backends.
stack-up:            ## start the daemons: OpenShell gateway + web UI (:8090)
	docker compose up -d openshell-gateway web

stack-run:           ## run one loop in a container (generate -> screen -> harden)
	docker compose run --rm orchestrator

stack-web:           ## just the web UI at http://localhost:8090
	docker compose up -d web

stack-ps:            ## show all stack containers (Up = daemon, Exited 0 = finished job)
	docker compose ps -a

stack-logs:          ## follow the daemons' logs
	docker compose logs -f openshell-gateway web

stack-down:          ## stop and remove the stack containers
	docker compose down

stack-clean: stack-down  ## also remove leftover sandbox containers
	-docker ps -aq --filter name=cdht-sandbox | xargs -r docker rm -f

clean:
	rm -rf runs .pytest_cache .coverage **/__pycache__
