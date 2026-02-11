FROM python:3.12-slim

# Install masscan and git
RUN apt-get update && \
    apt-get install -y --no-install-recommends masscan git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Clone the repo
RUN git clone -b feature/masscan-fingerprinting https://github.com/tt1a44a/HoneyCam.git /app/HoneyCam

WORKDIR /app/HoneyCam

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create output directories (will be overridden by volume mounts)
RUN mkdir -p logs captures

ENTRYPOINT ["python", "honeycam_scanner.py"]
