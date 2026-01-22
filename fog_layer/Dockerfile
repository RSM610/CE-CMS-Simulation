FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    iptables \
    iproute2 \
    net-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --default-timeout=3600 --retries=10 --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/results/logs /app/results/metrics

# Set environment variables
ENV PYTHONPATH=/app
ENV FLASK_APP=traffic_proxy.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=6000

# Expose port
EXPOSE 6000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:6000/health || exit 1

# Run the traffic proxy
CMD ["python", "traffic_proxy.py"]