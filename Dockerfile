# Honeypot System Dockerfile
# For educational purposes only

FROM python:3.11-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/database /app/logs

# Create non-root user for security
RUN useradd -m -u 1000 honeypot && \
    chown -R honeypot:honeypot /app

# Switch to non-root user
USER honeypot

# Expose ports
EXPOSE 22 80 2122 3306 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/api/stats', timeout=5)" || exit 1

# Default command (use Docker settings)
CMD ["python", "main_docker.py"] 