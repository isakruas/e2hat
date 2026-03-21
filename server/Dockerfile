FROM python:3.13-slim

WORKDIR /app

RUN pip install --no-cache-dir aiohttp ecutils

COPY server/ /app/server/

EXPOSE 8080

CMD ["python", "-m", "server.app"]
