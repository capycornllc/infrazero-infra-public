#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/infrazero-bootstrap.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[node1] $(date -Is) start"

load_env() {
  local file="$1"
  if [ -f "$file" ]; then
    set -a
    # shellcheck disable=SC1090
    source "$file"
    set +a
  fi
}

load_env /etc/infrazero/node.env
load_env /etc/infrazero/node1.env
load_env /etc/infrazero/network.env

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[node1] missing required env: $name" >&2
    exit 1
  fi
}

require_env "K3S_TOKEN"
require_env "EGRESS_LOKI_URL"

retry() {
  local attempts="$1"
  local delay="$2"
  shift 2
  local i
  for i in $(seq 1 "$attempts"); do
    if "$@"; then
      return 0
    fi
    echo "[node1] retry $i/$attempts failed; sleeping ${delay}s"
    sleep "$delay"
  done
  return 1
}

PRIVATE_CIDR="${PRIVATE_CIDR:-}"

detect_private_iface() {
  if [ -n "$PRIVATE_CIDR" ] && command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY'
import ipaddress
import os
import subprocess

cidr = os.environ.get("PRIVATE_CIDR", "")
try:
    net = ipaddress.ip_network(cidr, strict=False)
except Exception:
    raise SystemExit(1)
output = subprocess.check_output(["ip", "-4", "-o", "addr", "show"]).decode()
for line in output.splitlines():
    parts = line.split()
    if len(parts) < 4:
        continue
    ifname = parts[1]
    addr = parts[3].split("/")[0]
    try:
        if ipaddress.ip_address(addr) in net:
            print(ifname)
            raise SystemExit(0)
    except Exception:
        continue
raise SystemExit(1)
PY
    return
  fi

  ip -4 -o addr show | awk '$2 != "lo" {print $2; exit}'
}

PRIVATE_IF=$(detect_private_iface || true)
if [ -z "$PRIVATE_IF" ]; then
  echo "[node1] unable to determine private interface" >&2
  exit 1
fi

NODE_IP=$(ip -4 -o addr show dev "$PRIVATE_IF" | awk '{split($4, parts, "/"); print parts[1]; exit}')
if [ -z "$NODE_IP" ]; then
  echo "[node1] unable to determine private IP" >&2
  exit 1
fi

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl ca-certificates jq unzip apache2-utils
fi

K3S_SERVER_TAINT="${K3S_SERVER_TAINT:-false}"
INSTALL_K3S_EXEC="server --node-ip ${NODE_IP} --advertise-address ${NODE_IP} --flannel-iface ${PRIVATE_IF} --write-kubeconfig-mode 644"
if [ "${K3S_SERVER_TAINT,,}" = "true" ]; then
  INSTALL_K3S_EXEC="${INSTALL_K3S_EXEC} --node-taint node-role.kubernetes.io/control-plane=true:NoSchedule"
fi
if [ -n "${KUBERNETES_FQDN:-}" ]; then
  INSTALL_K3S_EXEC="${INSTALL_K3S_EXEC} --tls-san ${KUBERNETES_FQDN}"
fi

retry 10 5 curl -sfL https://get.k3s.io -o /tmp/k3s-install.sh
chmod +x /tmp/k3s-install.sh
INSTALL_K3S_EXEC="$INSTALL_K3S_EXEC" K3S_TOKEN="$K3S_TOKEN" /tmp/k3s-install.sh

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

for i in {1..60}; do
  if kubectl get nodes >/dev/null 2>&1; then
    if kubectl get nodes --no-headers 2>/dev/null | awk '$2=="Ready" {exit 0} END {exit 1}'; then
      break
    fi
  fi
  sleep 2
done

if kubectl -n kube-system get svc traefik >/dev/null 2>&1; then
  kubectl -n kube-system patch svc traefik --type merge -p '{"spec":{"type":"NodePort","ports":[{"name":"web","port":80,"protocol":"TCP","targetPort":"web","nodePort":30080},{"name":"websecure","port":443,"protocol":"TCP","targetPort":"websecure","nodePort":30443}]}}' || true
fi

if [ -n "${INFISICAL_FQDN:-}" ] || [ -n "${INFISICAL_SITE_URL:-}" ]; then
  if [ -f "./infisical-admin-secret.sh" ]; then
    chmod +x ./infisical-admin-secret.sh
    ./infisical-admin-secret.sh
  else
    echo "[node1] infisical-admin-secret.sh missing; skipping infisical admin secret sync" >&2
  fi
fi

kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
# Use server-side apply to avoid client-side last-applied annotations exceeding
# the 256KiB limit on large CRDs (e.g. ApplicationSet).
retry 10 5 kubectl apply --server-side --force-conflicts -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

for dep in argocd-server argocd-repo-server argocd-application-controller argocd-dex-server; do
  kubectl -n argocd rollout status "deployment/${dep}" --timeout=300s || true
done

if [ -n "${ARGOCD_ADMIN_PASSWORD:-}" ]; then
  if command -v htpasswd >/dev/null 2>&1; then
    admin_hash=$(htpasswd -nbBC 10 "" "$ARGOCD_ADMIN_PASSWORD" | tr -d ':\n')
    admin_mtime=$(date -Iseconds)
    patch_payload=$(jq -n --arg hash "$admin_hash" --arg mtime "$admin_mtime" '{stringData: {"admin.password": $hash, "admin.passwordMtime": $mtime}}')
    kubectl -n argocd patch secret argocd-secret --type merge -p "$patch_payload" || true
  else
    echo "[node1] htpasswd not available; skipping argocd admin password update" >&2
  fi
fi

kubectl -n argocd patch configmap argocd-cmd-params-cm --type merge -p '{"data":{"server.insecure":"true"}}' || true
kubectl -n argocd rollout restart deployment/argocd-server || true

if [ -n "${GH_TOKEN:-}" ] && [ -n "${ARGOCD_APP_REPO_URL:-}" ]; then
  repo_username="${GH_OWNER:-x-access-token}"
  cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Secret
metadata:
  name: argocd-repo-gitops
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  url: ${ARGOCD_APP_REPO_URL}
  username: ${repo_username}
  password: ${GH_TOKEN}
  name: gitops
EOF
fi

if [ -n "${ARGOCD_FQDN:-}" ]; then
  cat <<EOF | kubectl apply -f -
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: argocd-server
  namespace: argocd
  annotations:
    traefik.ingress.kubernetes.io/router.entrypoints: web
spec:
  ingressClassName: traefik
  rules:
  - host: ${ARGOCD_FQDN}
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: argocd-server
            port:
              number: 80
EOF
fi

if [ -n "${ARGOCD_APP_REPO_URL:-}" ] && [ -n "${ARGOCD_APP_PATH:-}" ]; then
  for i in {1..30}; do
    if kubectl get crd applications.argoproj.io >/dev/null 2>&1; then
      break
    fi
    sleep 2
  done
  app_name="${ARGOCD_APP_NAME:-root}"
  app_project="${ARGOCD_APP_PROJECT:-default}"
  app_revision="${ARGOCD_APP_REVISION:-main}"
  app_dest_namespace="${ARGOCD_APP_DEST_NAMESPACE:-argocd}"
  app_dest_server="${ARGOCD_APP_DEST_SERVER:-https://kubernetes.default.svc}"
  cat <<EOF | kubectl apply -f -
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: ${app_name}
  namespace: argocd
spec:
  project: ${app_project}
  source:
    repoURL: ${ARGOCD_APP_REPO_URL}
    targetRevision: ${app_revision}
    path: ${ARGOCD_APP_PATH}
  destination:
    server: ${app_dest_server}
    namespace: ${app_dest_namespace}
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
    - CreateNamespace=true
EOF
fi

# Promtail for journald to Loki
if [ ! -f /usr/local/bin/promtail ]; then
  if curl -fsSL -o /tmp/promtail.zip "https://github.com/grafana/loki/releases/download/v2.9.3/promtail-linux-amd64.zip"; then
    unzip -o /tmp/promtail.zip -d /usr/local/bin
    mv /usr/local/bin/promtail-linux-amd64 /usr/local/bin/promtail
    chmod +x /usr/local/bin/promtail
  else
    echo "[node1] promtail download failed; skipping"
  fi
fi

mkdir -p /etc/promtail /var/lib/promtail
cat > /etc/promtail/promtail.yml <<EOF
server:
  http_listen_port: 9080
  grpc_listen_port: 0
positions:
  filename: /var/lib/promtail/positions.yaml
clients:
  - url: ${EGRESS_LOKI_URL}
    external_labels:
      host: ${HOSTNAME}
      role: node1
scrape_configs:
  - job_name: journal
    journal:
      max_age: 12h
      labels:
        job: systemd-journal
    relabel_configs:
      - source_labels: ['__journal__systemd_unit']
        target_label: 'unit'
EOF

cat > /etc/systemd/system/promtail.service <<'EOF'
[Unit]
Description=Promtail log shipper
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/promtail -config.file=/etc/promtail/promtail.yml
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now promtail

echo "[node1] $(date -Is) complete"
