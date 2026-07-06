#!/bin/bash
# ═══════════════════════════════════════════════════════════════
# k8s-psa Evaluation Test Runner
# Deploys all 7 test pods, waits for 2 scan cycles, collects results
# ═══════════════════════════════════════════════════════════════
set -e

export NO_PROXY="${NO_PROXY},127.0.0.1,localhost,192.168.49.2"

echo "═══════════════════════════════════════════════════════"
echo "  k8s-psa Evaluation: Deploying 7 test pods"
echo "═══════════════════════════════════════════════════════"

# Clean up any old test pods
echo "[1/5] Cleaning up old test pods..."
for i in 1 2 3 4 5 6 7; do
  kubectl delete pod test-${i}-* --ignore-not-found 2>/dev/null || true
done
kubectl delete pod vulnerable-pod secure-pod --ignore-not-found 2>/dev/null || true
sleep 3

# Deploy all test pods
echo "[2/5] Deploying test pods..."
for f in tests/evaluation/pod-*.yaml; do
  echo "  Applying $f"
  kubectl apply -f "$f"
done
echo ""

# Wait for pods to be running
echo "[3/5] Waiting for pods to start..."
sleep 10
kubectl get pods -o wide
echo ""

# Wait for 2 full scan cycles (scan interval = 60s)
echo "[4/5] Waiting for 2 scan cycles (130 seconds)..."
echo "  The scanner runs every 60s. Waiting for it to detect all test pods."
sleep 130

# Collect results
echo "[5/5] Collecting results..."
echo ""

# Get the full log
LOG_FILE="evaluation_results_$(date +%Y%m%d_%H%M%S).log"
kubectl logs daemonset/k8s-psa -n k8s-psa-system > "$LOG_FILE" 2>&1

echo "═══════════════════════════════════════════════════════"
echo "  LAYER 1: Spec Violations per Test Pod"
echo "═══════════════════════════════════════════════════════"
for i in 1 2 3 4 5 6 7; do
  name=$(grep "test-${i}-" tests/evaluation/pod-${i}-*.yaml | head -1 | awk '{print $2}')
  count=$(grep "spec_violation" "$LOG_FILE" | grep "\"pod\": \"${name}\"" | head -20 | sort -u | wc -l)
  echo "  Pod ${i} (${name}): ${count} unique violations"
done
echo ""

echo "═══════════════════════════════════════════════════════"
echo "  LAYER 2: Drift Findings per Test Pod"
echo "═══════════════════════════════════════════════════════"
for i in 1 2 3 4 5 6 7; do
  name=$(grep "test-${i}-" tests/evaluation/pod-${i}-*.yaml | head -1 | awk '{print $2}')
  crit=$(grep "drift_finding" "$LOG_FILE" | grep "\"pod\": \"${name}\"" | grep '"severity": "critical"' | head -20 | sort -u | wc -l)
  warn=$(grep "drift_finding" "$LOG_FILE" | grep "\"pod\": \"${name}\"" | grep '"severity": "warning"' | head -50 | sort -u | wc -l)
  info=$(grep "drift_finding" "$LOG_FILE" | grep "\"pod\": \"${name}\"" | grep '"severity": "info"' | head -20 | sort -u | wc -l)
  echo "  Pod ${i} (${name}): CRITICAL=${crit}  WARNING=${warn}  INFO=${info}"
done
echo ""

echo "═══════════════════════════════════════════════════════"
echo "  LAYER 2: Detailed CRITICAL Drift Findings"
echo "═══════════════════════════════════════════════════════"
grep "drift_finding" "$LOG_FILE" | grep '"severity": "critical"' | python3 -c "
import sys, json
seen = set()
for line in sys.stdin:
    obj = json.loads(line)
    key = (obj['pod'], obj['field'])
    if key not in seen:
        seen.add(key)
        print(f\"  [{obj['severity'].upper()}] {obj['pod']}/{obj['container']}\")
        print(f\"    Field: {obj['field']}\")
        print(f\"    Declared: {obj['declared']}\")
        print(f\"    Actual:   {obj['actual']}\")
        print()
" 2>/dev/null || echo "  (no critical findings or parse error)"

echo ""
echo "═══════════════════════════════════════════════════════"
echo "  Raw log saved to: $LOG_FILE"
echo "  Generate dashboard: python3 analyze.py $LOG_FILE"
echo "═══════════════════════════════════════════════════════"
