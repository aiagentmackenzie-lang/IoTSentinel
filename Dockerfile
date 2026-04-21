FROM python:3.11-slim

# Non-root user - security hardening
RUN useradd -m -u 1000 iotsentinel
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ src/

# Never run as root
USER iotsentinel

ENTRYPOINT ["python", "-m", "src.cli.main"]
