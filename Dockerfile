# Nura judgment layer on Bedrock AgentCore Runtime: orchestrator + all sub-agents in one image.
# Built by `agentcore launch` in CodeBuild (ARM64); no local Docker needed. See deploy/README.md.
FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_NO_PROGRESS=1 \
    PYTHONPATH=/app/src \
    DOCKER_CONTAINER=1
# AWS_REGION is set per deployment by deploy_runtime.ps1 (agentcore launch --env).

# Dependencies first (cached layer): exact versions from uv.lock, agents extra, no dev tools.
COPY pyproject.toml uv.lock ./
RUN uv export --frozen --extra agents --no-dev --no-emit-project --no-hashes -o /tmp/requirements.txt \
 && uv pip install --system -r /tmp/requirements.txt \
 && rm /tmp/requirements.txt

RUN useradd -m -u 1000 bedrock_agentcore
USER bedrock_agentcore

# Code + rule catalog. routing.py finds /app/rulesets by default (src/agents/orchestrator -> /app).
COPY main.py ./
COPY src/ ./src/
COPY rulesets/ ./rulesets/

EXPOSE 8080
# ADOT auto-instrumentation -> CloudWatch GenAI Observability (aws-opentelemetry-distro is in the agents extra)
CMD ["opentelemetry-instrument", "python", "main.py"]
