FROM python:3.12-slim

LABEL maintainer="Security Architecture Team <sec-ops@apiguard.dev>"
LABEL description="Automated REST API Health & Security Compliance Linter"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Install dependencies first for Docker caching
COPY requirements.txt .
RUN pip install --upgrade pip && \
    pip install -r requirements.txt

# Copy source code and config
COPY pyproject.toml README.md ./
COPY src/ ./src/

# Install the package in editable/local mode
RUN pip install .

# Run as non-privileged user for security
RUN groupadd -r apiguard && useradd -r -g apiguard apiguard
USER apiguard

ENTRYPOINT ["apiguard"]
CMD ["--help"]
