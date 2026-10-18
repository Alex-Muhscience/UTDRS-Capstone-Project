FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as an unprivileged user
RUN useradd --create-home --uid 10001 utdrs
USER utdrs

EXPOSE 8000

# Run gunicorn for production; WEB_CONCURRENCY sets the number of workers (fewer on
# small instances: each is a full copy of the gateway).
ENV WEB_CONCURRENCY=4
CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "app:app"]
