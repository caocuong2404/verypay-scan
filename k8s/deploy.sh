#!/usr/bin/env bash
# Deploy supply-chain-scanner to K8s
# Usage: ./deploy.sh [--context verypay-test]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
CONTEXT="${1:-verypay-test}"
NAMESPACE="base"

echo "🚀 Deploying supply-chain-scanner"
echo "   Context:   $CONTEXT"
echo "   Namespace: $NAMESPACE"
echo ""

# Switch context
kubectl config use-context "$CONTEXT"

# Create namespace if needed
kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 || \
  kubectl create namespace "$NAMESPACE"

# Create ConfigMap from actual files (scan.sh, scan.ps1, index.html, report.html)
echo "📦 Creating ConfigMap from source files..."
kubectl create configmap scan-content-files \
  --namespace="$NAMESPACE" \
  --from-file=scan.sh="$PROJECT_DIR/scan.sh" \
  --from-file=scan.ps1="$PROJECT_DIR/scan.ps1" \
  --from-file=index.html="$PROJECT_DIR/www/index.html" \
  --from-file=report.html="$PROJECT_DIR/www/report.html" \
  --dry-run=client -o yaml | kubectl apply -f -

# Apply manifests (namespace, static configmap, deployment, service, ingress)
echo "📦 Applying K8s manifests..."
kubectl apply -f "$SCRIPT_DIR/deployment.yaml"

# Wait for rollout
echo "⏳ Waiting for rollout..."
kubectl rollout status deployment/supply-chain-scanner \
  --namespace="$NAMESPACE" --timeout=60s

echo ""
echo "✅ Deployed! Verify:"
echo "   kubectl get pods -n $NAMESPACE -l app=supply-chain-scanner"
echo "   kubectl get ingress -n $NAMESPACE"
echo ""
echo "🌐 URL: https://scan.dev.verypay.io"
echo "   curl -sSL https://scan.dev.verypay.io/scan.sh | bash"
