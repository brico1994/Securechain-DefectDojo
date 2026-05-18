FROM python:3.13-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV UV_LINK_MODE=copy
ENV PATH="/root/.local/bin:${PATH}"

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl ca-certificates git\
    && rm -rf /var/lib/apt/lists/*

RUN curl -LsSf https://astral.sh/uv/install.sh | sh

COPY pyproject.toml ./
COPY README.md ./

# Si aún no existe uv.lock, uv lo resolverá al sync
RUN uv sync --no-dev --no-install-project || true

COPY . .

RUN uv sync --no-dev

EXPOSE 8000

# No fijo el módulo ASGI para no inventarlo.
# Define APP_MODULE al ejecutar el contenedor.
ENV APP_MODULE=app.main:app

CMD ["sh", "-c", "uv run uvicorn ${APP_MODULE} --host 0.0.0.0 --port 8000"]
