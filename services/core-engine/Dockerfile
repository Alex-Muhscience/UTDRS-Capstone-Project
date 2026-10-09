FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# All dependencies (numpy, scipy, scikit-learn, yara-python) ship wheels for Python 3.12,
# so no compiler toolchain is needed in the image.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Run as an unprivileged user; the engine writes models and caches under /app.
RUN useradd --create-home --uid 10001 utdrs && chown -R utdrs /app
USER utdrs

EXPOSE 8000

# Run gunicorn for production
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app", "-k", "uvicorn.workers.UvicornWorker"]
