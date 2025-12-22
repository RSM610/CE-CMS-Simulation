FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy attack scripts
COPY . .

# Create necessary directories
RUN mkdir -p /app/results/logs /app/results/metrics

# Set environment variables
ENV PYTHONPATH=/app

# Default command runs all attack scenarios
CMD ["python", "run_attacks.py"]