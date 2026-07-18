.PHONY: test cov run docker-run clean

test:
	python3 -m pytest

cov:
	python3 -m pytest --cov=orchestrator --cov-report=term-missing

run:
	python3 -m orchestrator run --policy policies/baseline.yaml \
		--out runs/latest --save-policy runs/hardened.yaml

docker-run:
	docker compose up --build orchestrator

clean:
	rm -rf runs .pytest_cache .coverage **/__pycache__
