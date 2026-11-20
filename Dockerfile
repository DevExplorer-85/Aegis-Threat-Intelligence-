FROM mongo:7.0 AS mongodb-tools

FROM python:3.12-slim

# Reuse the Database Tools shipped in the official MongoDB image.
COPY --from=mongodb-tools /usr/bin/mongodump /usr/local/bin/mongodump
COPY --from=mongodb-tools /usr/bin/mongorestore /usr/local/bin/mongorestore
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgssapi-krb5-2 \
    && rm -rf /var/lib/apt/lists/*

ARG LAB_IMAGE=mongodb-labs:3.1
ARG LAB_ALLOWED_CHAPTERS=all
ARG LAB_VERSION=3.1
LABEL org.opencontainers.image.title="Aegis Intelligence – Chapters 7-18" \
      org.opencontainers.image.description="MongoDB Labs: CRUD, Aggregation, Indexing, ACID, Sharding, Security, Containers, Monitoring, Backup, Multi-Tenant Cases, Cassandra Audit, Neo4j Graph Investigations, Vector Search & RAG, Comparative Database Capstone" \
      org.opencontainers.image.version="${LAB_VERSION}" \
      org.opencontainers.image.source="${LAB_IMAGE}" \
      com.mongodb-labs.allowed-chapters="${LAB_ALLOWED_CHAPTERS}"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/backend \
    OUTPUT_DIR=/app/output \
    LAB_ALLOWED_CHAPTERS=${LAB_ALLOWED_CHAPTERS}

WORKDIR /app
COPY backend/requirements-core.txt /app/backend/requirements-core.txt
RUN pip install --no-cache-dir -r /app/backend/requirements-core.txt

COPY backend /app/backend
COPY frontend /app/frontend
COPY lab.py docker-compose.yml /app/
COPY chapter-12 /app/chapter-12
COPY chapter-13 /app/chapter-13
COPY chapter-14 /app/chapter-14
COPY chapter-15 /app/chapter-15
COPY chapter-16 /app/chapter-16
COPY chapter-17 /app/chapter-17
COPY chapter-18 /app/chapter-18
COPY tls /app/tls

RUN mkdir -p /app/output /app/output/results /app/output/jobs

WORKDIR /app/backend
ENTRYPOINT ["python", "/app/lab.py"]
