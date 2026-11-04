# Copyright (c) 2026 Amazon Web Services
# Licensed under the MIT-0 License
# See LICENSE file in the project root for full license information.
#
# Hosted image for Amazon Bedrock AgentCore Runtime (arm64).
# NOTE: For production, replace the base image with an internal ECR-hosted base image.
#checkov:skip=CKV_DOCKER_2:AgentCore Runtime checks container health through the /ping endpoint (see EXPOSE below), so no HEALTHCHECK instruction is declared
FROM public.ecr.aws/docker/library/python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt pyproject.toml README.md ./
COPY src ./src
RUN pip install -r requirements.txt && pip install --no-deps .

# Non-root user.
RUN useradd --system --create-home --uid 10001 nfi
USER nfi

# AgentCore Runtime talks to the container on 8080 (/invocations and /ping).
EXPOSE 8080
CMD ["python", "-m", "network_flow_insight.agentcore_app"]
