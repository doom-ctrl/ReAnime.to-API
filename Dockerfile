# ReAnime.to API - Dockerfile with Python + Node.js
FROM python:3.11-slim

# Install Node.js
RUN apt-get update && apt-get install -y curl \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Python files
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy Node.js decrypt script
COPY decrypt.mjs .

# Copy Python app
COPY reanime.py .

# Expose port
EXPOSE 8000

# Run the app - use Railway's PORT environment variable
CMD ["sh", "-c", "python -m uvicorn reanime:app --host 0.0.0.0 --port $PORT"]