.PHONY: test cov run ablate docker-run clean

test:
	uv run pytest

cov:
	uv run pytest --cov=orchestrator --cov-report=term-missing

run:
	uv run security-orchestrator run --out runs/latest --save-policy runs/hardened.yaml

ablate:
	uv run security-orchestrator ablate --out runs/ablation

docker-run:
	docker compose up --build orchestrator

clean:
	rm -rf runs .pytest_cache .coverage **/__pycache__
