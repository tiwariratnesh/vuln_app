# Use Python 3.9 with known vulnerabilities in dependencies
FROM python:3.9-slim

# Install system packages
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    vim \
    openssh-client \
    git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

# Run as root (security misconfiguration)
USER root

# Expose port
EXPOSE 5000

# Environment variables with sensitive data
ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1
ENV DATABASE_URL=postgresql://admin:password123@db:5432/appdb
ENV SECRET_KEY=insecure-secret-key-12345
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE

CMD ["python", "app.py"]
