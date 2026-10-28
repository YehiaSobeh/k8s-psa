#!/bin/bash
set -e

echo "═══════════════════════════════════════════════════════"
echo "  k8s-psa: Building and deploying"
echo "═══════════════════════════════════════════════════════"

# Fix proxy for Minikube
export NO_PROXY="${NO_PROXY},127.0.0.1,localhost,192.168.49.2"

# 1. Build scanner image
echo "[1/6] Building scanner image..."
docker build -t k8s-psa:latest .

# 2. Build dashboard image
echo "[2/6] Building dashboard image..."
docker build -t k8s-psa-dashboard:latest dashboard/

# 3. Load into Minikube
echo "[3/6] Loading images into Minikube..."
minikube image load k8s-psa:latest
minikube image load k8s-psa-dashboard:latest

# 4. Clean up old deployment (if any)
echo "[4/6] Cleaning up old deployment..."
kubectl delete namespace k8s-psa-system --ignore-not-found 2>/dev/null || true
sleep 3

# 5. Deploy everything
echo "[5/6] Deploying scanner + dashboard..."
kubectl apply -f deployments/all-in-one.yaml
kubectl create configmap k8s-psa-policies \
  --from-file=policies/default.yaml \
  -n k8s-psa-system

# 6. Wait for pods
echo "[6/6] Waiting for pods to start..."
kubectl rollout status daemonset/k8s-psa -n k8s-psa-system --timeout=120s
kubectl rollout status deployment/k8s-psa-dashboard -n k8s-psa-system --timeout=120s

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Deployed successfully!"
echo ""
echo "  Scanner logs:"
echo "    kubectl logs -l app=k8s-psa -n k8s-psa-system -f"
echo ""
echo "  Open the live dashboard:"
echo "    kubectl port-forward svc/k8s-psa-dashboard 8080:8080 -n k8s-psa-system"
echo "    Then open: http://localhost:8080"
echo "═══════════════════════════════════════════════════════"
