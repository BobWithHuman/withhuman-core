# The graph viewer as a container on the engine's Compose network, so PostgreSQL needs no host
# port and the host no Python packages. Compose publishes it on 127.0.0.1 only.
FROM python:3.12-slim

RUN pip install --no-cache-dir "psycopg[binary]==3.2.3" \
 && useradd --system --uid 10001 viewer

COPY server.py index.html /app/

USER viewer
ENV VIEWER_ADDR=0.0.0.0 \
    VIEWER_PORT=7480
EXPOSE 7480
CMD ["python", "-I", "/app/server.py"]
