FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir pydantic pydantic-settings fastapi uvicorn sqlalchemy redis neo4j psutil networkx requests httpx

COPY . .

EXPOSE 8050

CMD ["uvicorn", "chronos.api.app:app", "--host", "0.0.0.0", "--port", "8050"]
