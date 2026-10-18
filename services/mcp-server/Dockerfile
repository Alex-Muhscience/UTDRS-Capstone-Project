FROM python:3.12-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY gateway.py server.py app.py ./

# Run as an unprivileged user
RUN useradd --create-home --uid 10001 utdrs
USER utdrs

EXPOSE 8765

ENV MCP_HOST=0.0.0.0 MCP_PORT=8765
CMD ["python", "app.py"]
