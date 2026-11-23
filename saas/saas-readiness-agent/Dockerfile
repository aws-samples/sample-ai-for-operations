# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
#
# Container image for the published v2 profile on Amazon Bedrock AgentCore
# Runtime. AgentCore Runtime requires linux/arm64 and calls the container on
# port 8080 (/invocations, /ping).
#
# Build with `docker buildx build --platform linux/arm64 ...` (see README).
#
# The base image is pinned to the multi-arch index digest of python:3.12-slim
# for reproducible builds. To update it, run
#   docker buildx imagetools inspect public.ecr.aws/docker/library/python:3.12-slim
# and replace the digest below.
#
# NOTE: For production, replace the public base image with one hosted in your
# organization's approved private Amazon ECR registry, pinned by digest.
FROM public.ecr.aws/docker/library/python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # Build-time install runs as root by design; the image runs as uid 10001.
    PIP_ROOT_USER_ACTION=ignore \
    # Tells the AgentCore SDK it is containerized so it binds inside the
    # container network. The container publishes no host port by itself;
    # AgentCore Runtime is the only ingress and enforces inbound auth.
    DOCKER_CONTAINER=1

WORKDIR /app

# Install pinned dependencies first for better layer caching.
COPY requirements.txt .
RUN pip install -r requirements.txt

COPY src/ ./src/

# Run as a dedicated non-root user. reports/ is the only path the agent's
# report tools write to.
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /app/reports \
    && chown appuser /app/reports
USER 10001

EXPOSE 8080

# Container-level health check against the runtime's own /ping endpoint on
# loopback. AgentCore Runtime performs its own /ping checks; this one serves
# local and other container runtimes. Uses the standard library (no curl in
# the slim image).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/ping', timeout=4).status == 200 else 1)"]

CMD ["python", "-m", "src.runtime"]
