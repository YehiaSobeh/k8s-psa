FROM python:3.9-slim

WORKDIR /app

# Install kubectl, crictl, AND docker CLI
# The tool auto-detects which runtime is available
RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    && curl -LO "https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl" \
    && install -o root -g root -m 0755 kubectl /usr/local/bin/kubectl \
    && curl -L https://github.com/kubernetes-sigs/cri-tools/releases/download/v1.29.0/crictl-v1.29.0-linux-amd64.tar.gz \
    | tar -xz -C /usr/local/bin \
    && curl -fsSL https://download.docker.com/linux/static/stable/x86_64/docker-27.4.1.tgz \
    | tar -xz --strip-components=1 -C /usr/local/bin docker/docker \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# crictl config (in case containerd is used)
ENV CONTAINER_RUNTIME_ENDPOINT=unix:///var/run/containerd/containerd.sock

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY policies/ ./policies/

CMD ["python", "-m", "src.main"]
