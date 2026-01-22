FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --default-timeout=3600 --retries=10 --no-cache-dir -r requirements.txt
COPY shutdown_simulation.py .

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/results/logs /app/results/reports /app/results/metrics

# Set environment variables
ENV PYTHONPATH=/app
ENV FLASK_APP=logger.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV FLASK_RUN_PORT=8000

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run the metrics logger
CMD ["python", "logger.py"]