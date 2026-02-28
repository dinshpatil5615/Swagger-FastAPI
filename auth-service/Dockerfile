# Base image
FROM python:3.11-slim

# Environmernt variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONBUFFERED=1

# Working directory
WORKDIR /code

# install system dependencies
RUN apt-get update -y && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
  && pip install --no-cache-dir -r requirements.txt

# copy application code
COPY . .

# create non-root user
RUN useradd -m appuser

# create writable directory fopr sqlite
RUN mkdir -p /code/data && chown -R appuser:appuser /code

# switch to appuser
USER appuser

# Expose port
EXPOSE 8000

# Start application
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8000"]