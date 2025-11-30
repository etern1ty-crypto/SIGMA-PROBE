# Build stage
FROM python:3.9-slim as builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install poetry
RUN pip install poetry

# Copy configuration
COPY pyproject.toml README.md ./

# Export requirements and install
# We use this approach to avoid installing poetry in the final image
RUN poetry config virtualenvs.create false \
    && poetry install --no-dev --no-interaction --no-ansi

# Runtime stage
FROM python:3.9-slim

WORKDIR /app

# Create non-root user
RUN groupadd -r sigma && useradd -r -g sigma sigma

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.9/site-packages /usr/local/lib/python3.9/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY src ./src
COPY config.yaml .

# Set ownership
RUN chown -R sigma:sigma /app

USER sigma

# Environment variables
ENV PYTHONUNBUFFERED=1

# Entry point
CMD ["python", "-m", "src.main"]
