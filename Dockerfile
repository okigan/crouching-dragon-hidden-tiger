# Orchestrator image: our code + the openshell CLI + the HiddenLayer SDK.
FROM python:3.12-slim

# Unbuffered stdout/stderr so a run's progress streams to `docker logs` live
# (otherwise Python buffers until exit and the container looks log-less mid-run).
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# curl for health checks; openssh-client because the openshell CLI relays into
# a sandbox over ssh (ProxyCommand back through the gateway) — without it,
# `openshell sandbox create` fails at "Waiting for supervisor relay".
RUN apt-get update && apt-get install -y --no-install-recommends curl openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Deps first for layer caching.
COPY pyproject.toml README.md ./
COPY orchestrator ./orchestrator
COPY policies ./policies
COPY third_party ./third_party

# Install our package (with the HiddenLayer extra) and the OpenShell CLI so the
# OpenShellSandbox adapter can drive a gateway.
RUN pip install --no-cache-dir ".[hiddenlayer,web]" openshell

# Real backends are the default in deployment; mocks are for the test suite.
# Backend selection + credentials come from the environment (.env via compose).
ENTRYPOINT ["security-orchestrator"]
CMD ["run", "--generate", "5", "--out", "/app/runs/latest", \
     "--save-policy", "/app/runs/latest/hardened.yaml"]
