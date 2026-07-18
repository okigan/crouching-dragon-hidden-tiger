FROM python:3.12-slim

WORKDIR /app

# Deps first for layer caching.
COPY pyproject.toml ./
RUN pip install --no-cache-dir PyYAML>=6.0 pytest>=8

COPY orchestrator ./orchestrator
COPY policies ./policies
COPY tests ./tests

# Default backends are mocks, so this runs fully self-contained.
ENTRYPOINT ["python", "-m", "orchestrator"]
CMD ["run", "--policy", "policies/baseline.yaml", "--out", "/app/runs/latest", "--save-policy", "/app/runs/hardened.yaml"]
