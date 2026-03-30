FROM python:3.9-slim

WORKDIR /app

# Install kubectl and crictl
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    && curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
    && install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl \
    && curl -L https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.24.0/crictl-v1.24.0-linux-amd64.tar.gz \
    | tar -xz -C /usr/local/bin \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY policies/ ./policies/

# Create non-root user
RUN useradd -m -u 1000 k8spsa
USER 1000

CMD ["python", "-m", "src.main"]