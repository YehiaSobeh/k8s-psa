# Fix proxy
export NO_PROXY=$NO_PROXY,127.0.0.1,localhost,192.168.49.2

docker build -t k8s-psa:latest .
minikube image load k8s-psa:latest

# Deploy everything (scanner + dashboard + test pods + collect results)
bash deploy.sh
bash tests/evaluation/run-evaluation.sh

# Open the live dashboard
kubectl port-forward svc/k8s-psa-dashboard 8080:8080 -n k8s-psa-system