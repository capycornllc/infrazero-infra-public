#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/infrazero-bootstrap.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[node1] $(date -Is) start"

BOOTSTRAP_ROLE="node1"

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
  beacon_status "installing_packages" "Installing packages" 10
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl ca-certificates jq unzip apache2-utils openssl
fi

if ! command -v argocd >/dev/null 2>&1; then
  ARGOCD_CLI_VERSION="${ARGOCD_CLI_VERSION:-latest}"
  if [ "$ARGOCD_CLI_VERSION" = "latest" ]; then
    ARGOCD_CLI_URL="https://github.com/argoproj/argo-cd/releases/latest/download/argocd-linux-amd64"
  else
    ARGOCD_CLI_URL="https://github.com/argoproj/argo-cd/releases/download/${ARGOCD_CLI_VERSION}/argocd-linux-amd64"
  fi
  if retry 5 2 curl -fsSL -o /usr/local/bin/argocd "$ARGOCD_CLI_URL"; then
    chmod +x /usr/local/bin/argocd
  else
    echo "[node1] argocd cli download failed; skipping" >&2
  fi
fi

K3S_SERVER_TAINT="${K3S_SERVER_TAINT:-false}"
K3S_CONTROL_PLANES_COUNT="${K3S_CONTROL_PLANES_COUNT:-1}"
INSTALL_K3S_EXEC="server --node-ip ${NODE_IP} --advertise-address ${NODE_IP} --flannel-iface ${PRIVATE_IF} --write-kubeconfig-mode 644"
if [ "${K3S_SERVER_TAINT,,}" = "true" ]; then
  INSTALL_K3S_EXEC="${INSTALL_K3S_EXEC} --node-taint node-role.kubernetes.io/control-plane=true:NoSchedule"
fi
if [ "${K3S_CONTROL_PLANES_COUNT}" -gt 1 ]; then
  INSTALL_K3S_EXEC="${INSTALL_K3S_EXEC} --cluster-init"
fi
if [ -n "${K3S_API_LB_PRIVATE_IP:-}" ]; then
  INSTALL_K3S_EXEC="${INSTALL_K3S_EXEC} --tls-san ${K3S_API_LB_PRIVATE_IP}"
fi
if [ -n "${KUBERNETES_FQDN:-}" ]; then
  INSTALL_K3S_EXEC="${INSTALL_K3S_EXEC} --tls-san ${KUBERNETES_FQDN}"
fi

retry 10 5 curl -sfL https://get.k3s.io -o /tmp/k3s-install.sh
chmod +x /tmp/k3s-install.sh

install_k3s() {
  beacon_status "installing_k3s" "Installing K3s" 30
  local attempts=5
  local delay=10
  local i
  for i in $(seq 1 "$attempts"); do
    set +e
    INSTALL_K3S_EXEC="$INSTALL_K3S_EXEC" K3S_TOKEN="$K3S_TOKEN" /tmp/k3s-install.sh
    local rc=$?
    set -e

    if [ "$rc" -eq 0 ]; then
      return 0
    fi

    # systemctl can report failure even if k3s restarts successfully.
    for _ in {1..6}; do
      if systemctl is-active --quiet k3s; then
        echo "[node1] k3s installer failed (rc=$rc) but k3s service is active; continuing"
        return 0
      fi
      sleep 5
    done

    echo "[node1] k3s install attempt $i/$attempts failed (rc=$rc)"
    systemctl status k3s --no-pager || true
    journalctl -u k3s -b --no-pager -n 200 || true

    if [ "$i" -lt "$attempts" ]; then
      echo "[node1] retrying k3s install in ${delay}s"
      sleep "$delay"
      delay=$((delay * 2))
      if [ "$delay" -gt 120 ]; then
        delay=120
      fi
    fi
  done

  return 1
}

install_k3s

export KUBECONFIG=/etc/rancher/k3s/k3s.yaml

beacon_status "waiting_k3s_ready" "Waiting for K3s nodes" 45

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

if [ -n "${GHCR_TOKEN:-}" ] && [ -n "${GH_OWNER:-}" ]; then
  kubectl -n default create secret docker-registry ghcr-pull \
    --docker-server=ghcr.io \
    --docker-username="$GH_OWNER" \
    --docker-password="$GHCR_TOKEN" \
    --dry-run=client -o yaml | kubectl apply -f -
else
  echo "[node1] GHCR_TOKEN or GH_OWNER missing; skipping ghcr-pull secret" >&2
fi

if [ -n "${INFISICAL_FQDN:-}" ] || [ -n "${INFISICAL_SITE_URL:-}" ]; then
  if [ -f "./infisical-admin-secret.sh" ]; then
    chmod +x ./infisical-admin-secret.sh
    infisical_ok=false
    for infisical_attempt in 1 2 3; do
      echo "[node1] infisical-admin-secret.sh attempt ${infisical_attempt}/3"
      if ./infisical-admin-secret.sh; then
        infisical_ok=true
        break
      fi
      echo "[node1] infisical-admin-secret.sh failed (attempt ${infisical_attempt}/3); retrying in 60s" >&2
      sleep 60
    done
    if [ "$infisical_ok" != "true" ]; then
      echo "[node1] WARNING: infisical-admin-secret.sh failed after 3 attempts; continuing without it" >&2
    fi
  else
    echo "[node1] infisical-admin-secret.sh missing; skipping infisical admin secret sync" >&2
  fi
fi

kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
beacon_status "deploying_argocd" "Deploying ArgoCD" 55
# Use server-side apply to avoid client-side last-applied annotations exceeding
# the 256KiB limit on large CRDs (e.g. ApplicationSet).
retry 10 5 kubectl apply --server-side --force-conflicts -n argocd -f https://raw.githubusercontent.com/argoproj/argo-cd/stable/manifests/install.yaml

for dep in argocd-server argocd-repo-server argocd-application-controller argocd-dex-server; do
  kubectl -n argocd rollout status "deployment/${dep}" --timeout=300s || true
done

# Expose ArgoCD server via NodePort so egress nginx can proxy to it
kubectl -n argocd patch svc argocd-server --type=merge -p '{"spec":{"type":"NodePort"}}' || true
echo "[node1] ArgoCD server exposed via NodePort"

if [ -n "${ARGOCD_FQDN:-}" ]; then
  argocd_url_patch=$(jq -n --arg url "https://${ARGOCD_FQDN}" '{data:{"url":$url}}')
  kubectl -n argocd patch configmap argocd-cm --type merge -p "$argocd_url_patch" || true
fi

if [ -n "${ARGOCD_ADMIN_PASSWORD:-}" ]; then
  if command -v htpasswd >/dev/null 2>&1; then
    admin_hash=$(printf '%s\n' "$ARGOCD_ADMIN_PASSWORD" | htpasswd -niBC 10 "" | tr -d ':\n')
    admin_mtime=$(date -Iseconds)
    patch_payload=$(jq -n --arg hash "$admin_hash" --arg mtime "$admin_mtime" '{stringData: {"admin.password": $hash, "admin.passwordMtime": $mtime}}')
    kubectl -n argocd patch secret argocd-secret --type merge -p "$patch_payload" || true
  else
    echo "[node1] htpasswd not available; skipping argocd admin password update" >&2
  fi
fi

configure_argocd_local_users_from_platform_admins() {
  if [ -z "${PLATFORM_ADMINS_JSON:-}" ]; then
    return 0
  fi
  if ! command -v jq >/dev/null 2>&1; then
    echo "[node1] jq not available; skipping Argo CD per-admin bootstrap" >&2
    return 0
  fi
  if ! command -v htpasswd >/dev/null 2>&1; then
    echo "[node1] htpasswd not available; skipping Argo CD per-admin bootstrap" >&2
    return 0
  fi

  local entries_tmp rbac_tmp dex_secret_tmp
  entries_tmp=$(mktemp)
  rbac_tmp=$(mktemp)
  dex_secret_tmp=$(mktemp)
  chmod 600 "$entries_tmp"
  chmod 600 "$rbac_tmp"
  chmod 600 "$dex_secret_tmp"

  echo "$PLATFORM_ADMINS_JSON" | jq -c '.[]?' | while read -r admin; do
    local email password read_only hash user_id role hash_secret_key hash_ref
    email=$(echo "$admin" | jq -r '.email // empty')
    password=$(echo "$admin" | jq -r '.argocd_password // empty')
    read_only=$(echo "$admin" | jq -r '.argocd_read_only // false')
    if [ -z "$email" ] || [ -z "$password" ]; then
      continue
    fi
    hash=$(printf '%s\n' "$password" | htpasswd -niBC 10 "" | tr -d ':\n')
    # Dex expects bcrypt hashes with $2a$/$2b$ prefix; apache htpasswd emits $2y$.
    hash="${hash/\$2y\$/\$2a\$}"
    user_id=$(printf '%s' "$email" | sha1sum | awk '{print $1}' | sed -E 's/^(.{8})(.{4})(.{4})(.{4})(.{12}).*$/\1-\2-\3-\4-\5/')
    hash_secret_key="dex.local.users.${user_id}.hash"
    hash_ref="\$${hash_secret_key}"
    role="role:admin"
    if [ "${read_only,,}" = "true" ]; then
      role="role:readonly"
    fi
    jq -nc \
      --arg email "$email" \
      --arg hash "$hash_ref" \
      --arg username "$email" \
      --arg user_id "$user_id" \
      '{email:$email, hash:$hash, username:$username, userID:$user_id}' \
      >> "$entries_tmp"
    jq -nc --arg k "$hash_secret_key" --arg v "$hash" '{($k):$v}' >> "$dex_secret_tmp"
    printf 'g, %s, %s\n' "$user_id" "$role" >> "$rbac_tmp"
  done

  if [ ! -s "$entries_tmp" ]; then
    echo "[node1] PLATFORM_ADMINS_JSON set but no valid Argo CD admin entries found; skipping"
    rm -f "$entries_tmp"
    rm -f "$rbac_tmp"
    rm -f "$dex_secret_tmp"
    return 0
  fi

  local static_passwords dex_config oidc_config cm_patch rbac_csv rbac_patch dex_secret_data dex_secret_patch
  local server_secret_b64 current_dex_oauth2_b64 current_dex_oauth2_client_secret dex_oauth2_client_secret dex_oauth2_patch
  static_passwords=$(jq -cs '.' "$entries_tmp")
  dex_secret_data=$(jq -sc 'reduce .[] as $item ({}; . * $item)' "$dex_secret_tmp")
  dex_secret_patch=$(jq -n --argjson data "$dex_secret_data" '{stringData:$data}')
  kubectl -n argocd patch secret argocd-secret --type merge -p "$dex_secret_patch" || true
  server_secret_b64=$(kubectl -n argocd get secret argocd-secret -o json | jq -r '.data["server.secretkey"] // empty' || true)
  if [ -n "$server_secret_b64" ]; then
    dex_oauth2_client_secret=$(
      printf '%s' "$server_secret_b64" \
      | base64 -d \
      | openssl dgst -sha256 -binary \
      | openssl base64 -A \
      | tr '+/' '-_' \
      | cut -c1-40
    )
    current_dex_oauth2_b64=$(kubectl -n argocd get secret argocd-secret -o json | jq -r '.data["dex.oauth2.clientSecret"] // empty' || true)
    current_dex_oauth2_client_secret=""
    if [ -n "$current_dex_oauth2_b64" ]; then
      current_dex_oauth2_client_secret=$(printf '%s' "$current_dex_oauth2_b64" | base64 -d 2>/dev/null || true)
    fi
    if [ "$current_dex_oauth2_client_secret" != "$dex_oauth2_client_secret" ]; then
      dex_oauth2_patch=$(jq -n --arg v "$dex_oauth2_client_secret" '{stringData:{"dex.oauth2.clientSecret":$v}}')
      kubectl -n argocd patch secret argocd-secret --type merge -p "$dex_oauth2_patch" || true
    fi
  fi
  dex_config=$(jq -cn \
    --argjson static_passwords "$static_passwords" \
    '{connectors:[],enablePasswordDB:true,staticPasswords:$static_passwords}')
  if [ -n "${ARGOCD_FQDN:-}" ]; then
    oidc_config=$(cat <<EOF
name: Local
issuer: https://${ARGOCD_FQDN}/api/dex
clientID: argo-cd
clientSecret: \$dex.oauth2.clientSecret
requestedScopes:
  - openid
  - profile
  - email
  - groups
EOF
)
    cm_patch=$(jq -n \
      --arg dex_config "$dex_config" \
      --arg oidc_config "$oidc_config" \
      '{data:{"dex.config":$dex_config,"oidc.config":$oidc_config,"admin.enabled":"true"}}')
  else
    cm_patch=$(jq -n --arg dex_config "$dex_config" '{data:{"dex.config":$dex_config,"admin.enabled":"true"}}')
  fi
  kubectl -n argocd patch configmap argocd-cm --type merge -p "$cm_patch" || true

  rbac_csv=$'g, admin, role:admin'
  if [ -s "$rbac_tmp" ]; then
    rbac_csv="${rbac_csv}"$'\n'"$(sort -u "$rbac_tmp")"
  fi
  rbac_patch=$(jq -n \
    --arg policy_csv "$rbac_csv" \
    '{data:{"policy.csv":$policy_csv,"policy.default":"role:readonly","scopes":"[groups]"}}')
  kubectl -n argocd patch configmap argocd-rbac-cm --type merge -p "$rbac_patch" || true

  kubectl -n argocd rollout restart deployment/argocd-dex-server || true
  kubectl -n argocd rollout restart deployment/argocd-server || true
  kubectl -n argocd rollout status deployment/argocd-dex-server --timeout=300s || true
  kubectl -n argocd rollout status deployment/argocd-server --timeout=300s || true
  rm -f "$entries_tmp"
  rm -f "$rbac_tmp"
  rm -f "$dex_secret_tmp"
}

beacon_status "configuring_argocd" "Configuring ArgoCD users" 70

configure_argocd_local_users_from_platform_admins

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

# Promtail for journald to Loki (optional)
if [ ! -x /usr/local/bin/promtail ]; then
  if curl -fsSL -o /tmp/promtail.zip "https://github.com/grafana/loki/releases/download/v2.9.3/promtail-linux-amd64.zip"; then
    unzip -o /tmp/promtail.zip -d /usr/local/bin
    mv /usr/local/bin/promtail-linux-amd64 /usr/local/bin/promtail
    chmod +x /usr/local/bin/promtail
  else
    echo "[node1] promtail download failed; skipping"
  fi
fi

if [ -x /usr/local/bin/promtail ]; then
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
systemctl enable --now promtail || echo "[node1] failed to start promtail; continuing"
else
  echo "[node1] promtail binary unavailable; skipping service setup"
fi

beacon_status "validating_certs" "Validating TLS certificates" 85

# ── Certificate validation ──────────────────────────────────────────
# Wait for cert-manager to issue certificates after ArgoCD sync.
# If rate limit is hit, log a clear error so it's visible in Loki/monitoring.
echo "[node1] $(date -Is) starting certificate validation"

cert_check() {
  local max_wait=300
  local interval=15
  local elapsed=0

  # Wait for cert-manager CRD to appear (ArgoCD may still be syncing)
  echo "[node1] waiting for cert-manager CRDs..."
  while [ "$elapsed" -lt 120 ]; do
    if kubectl get crd certificates.cert-manager.io >/dev/null 2>&1; then
      echo "[node1] cert-manager CRDs found"
      break
    fi
    sleep 10
    elapsed=$((elapsed + 10))
  done

  if ! kubectl get crd certificates.cert-manager.io >/dev/null 2>&1; then
    echo "[node1] WARNING: cert-manager CRDs not found after 120s — certificate validation skipped"
    return 0
  fi

  # Wait for certificates to appear
  elapsed=0
  while [ "$elapsed" -lt 60 ]; do
    local count
    count=$(kubectl get certificates --all-namespaces --no-headers 2>/dev/null | wc -l || echo "0")
    if [ "$count" -gt 0 ]; then
      break
    fi
    sleep 10
    elapsed=$((elapsed + 10))
  done

  # Poll certificates until all ready or timeout
  elapsed=0
  while [ "$elapsed" -lt "$max_wait" ]; do
    local all_ready=true
    local has_rate_limit=false
    local cert_summary=""

    while IFS= read -r line; do
      local ns name ready message domain
      ns=$(echo "$line" | jq -r '.metadata.namespace')
      name=$(echo "$line" | jq -r '.metadata.name')
      ready=$(echo "$line" | jq -r '.status.conditions[]? | select(.type=="Ready") | .status' 2>/dev/null || echo "")
      message=$(echo "$line" | jq -r '.status.conditions[]? | select(.type=="Ready") | .message' 2>/dev/null || echo "")
      domain=$(echo "$line" | jq -r '.spec.dnsNames[0] // "unknown"')

      if [ "$ready" = "True" ]; then
        cert_summary="${cert_summary}  ✓ ${domain} (${ns}/${name})\n"
      else
        all_ready=false
        cert_summary="${cert_summary}  ✗ ${domain} (${ns}/${name}): ${message}\n"
        if echo "$message" | grep -qiE "rate limit|too many certificates|too many requests"; then
          has_rate_limit=true
        fi
      fi
    done < <(kubectl get certificates --all-namespaces -o json 2>/dev/null | jq -c '.items[]')

    if [ "$has_rate_limit" = "true" ]; then
      echo "[node1] =========================================="
      echo "[node1] CERTIFICATE ERROR: Let's Encrypt rate limit reached"
      echo -e "[node1] Certificate status:\n${cert_summary}"
      echo "[node1] Sites without certificates will show 'connection not secure' warnings."
      echo "[node1] Wait at least 1 hour before retrying. See: https://letsencrypt.org/docs/rate-limits/"
      echo "[node1] =========================================="
      return 0
    fi

    if [ "$all_ready" = "true" ]; then
      echo "[node1] All certificates are ready:"
      echo -e "$cert_summary"
      return 0
    fi

    echo "[node1] Waiting for certificates... (${elapsed}s/${max_wait}s)"
    sleep "$interval"
    elapsed=$((elapsed + interval))
  done

  echo "[node1] =========================================="
  echo "[node1] CERTIFICATE WARNING: Not all certificates ready after ${max_wait}s"
  local cert_summary=""
  while IFS= read -r line; do
    local ns name ready message domain
    ns=$(echo "$line" | jq -r '.metadata.namespace')
    name=$(echo "$line" | jq -r '.metadata.name')
    ready=$(echo "$line" | jq -r '.status.conditions[]? | select(.type=="Ready") | .status' 2>/dev/null || echo "")
    message=$(echo "$line" | jq -r '.status.conditions[]? | select(.type=="Ready") | .message' 2>/dev/null || echo "")
    domain=$(echo "$line" | jq -r '.spec.dnsNames[0] // "unknown"')
    if [ "$ready" = "True" ]; then
      echo "[node1]   ✓ ${domain} (${ns}/${name})"
    else
      echo "[node1]   ✗ ${domain} (${ns}/${name}): ${message}"
    fi
  done < <(kubectl get certificates --all-namespaces -o json 2>/dev/null | jq -c '.items[]')
  echo "[node1] Sites without valid certificates will show 'connection not secure' warnings."
  echo "[node1] =========================================="
}

cert_check || echo "[node1] certificate validation encountered an error; continuing"

# ------------------------------------------------------------------ #
#  Dedicated etcd for Patroni (optional)                               #
# ------------------------------------------------------------------ #

setup_etcd_patroni() {
  local enabled="${ETCD_PATRONI_ENABLED:-false}"
  if [ "$enabled" != "true" ]; then
    echo "[node1] etcd-patroni not enabled; skipping"
    return 0
  fi

  echo "[node1] installing dedicated etcd for Patroni"

  local etcd_version="${ETCD_PATRONI_VERSION:-3.5.21}"
  local etcd_name="${ETCD_PATRONI_NAME:-$(hostname)}"
  local initial_cluster="${ETCD_PATRONI_INITIAL_CLUSTER:-}"
  local client_port="${ETCD_PATRONI_CLIENT_PORT:-2391}"
  local peer_port="${ETCD_PATRONI_PEER_PORT:-2392}"

  if [ -z "$initial_cluster" ]; then
    echo "[node1] ETCD_PATRONI_INITIAL_CLUSTER not set; cannot configure etcd" >&2
    return 1
  fi

  # Resolve private IP
  local advertise_ip=""
  if [ -n "${PRIVATE_CIDR:-}" ] && command -v python3 >/dev/null 2>&1; then
    advertise_ip=$(python3 - <<'PY'
import ipaddress, os, subprocess
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
    addr = parts[3].split("/")[0]
    try:
        if ipaddress.ip_address(addr) in net:
            print(addr)
            raise SystemExit(0)
    except Exception:
        continue
raise SystemExit(1)
PY
    ) || true
  fi

  if [ -z "$advertise_ip" ]; then
    echo "[node1] unable to determine private IP for etcd advertise" >&2
    return 1
  fi

  # Download etcd
  local arch="amd64"
  local etcd_url="https://github.com/etcd-io/etcd/releases/download/v${etcd_version}/etcd-v${etcd_version}-linux-${arch}.tar.gz"
  local tmpdir
  tmpdir=$(mktemp -d)

  echo "[node1] downloading etcd v${etcd_version}"
  timeout 120 curl -fsSL "$etcd_url" -o "${tmpdir}/etcd.tar.gz"
  tar -xzf "${tmpdir}/etcd.tar.gz" -C "${tmpdir}" --strip-components=1
  install -m 0755 "${tmpdir}/etcd" /usr/local/bin/etcd-patroni
  install -m 0755 "${tmpdir}/etcdctl" /usr/local/bin/etcdctl-patroni
  rm -rf "${tmpdir}"

  # Data directory
  mkdir -p /var/lib/etcd-patroni
  chmod 700 /var/lib/etcd-patroni

  # Verify ports are free before starting
  for check_port in "$client_port" "$peer_port"; do
    if ss -tlnp | grep -q ":${check_port} "; then
      local occupant
      occupant=$(ss -tlnp | grep ":${check_port} " | head -1)
      echo "[node1] ERROR: port ${check_port} already in use: ${occupant}" >&2
      echo "[node1] etcd-patroni cannot start — pick different ports via ETCD_PATRONI_CLIENT_PORT / ETCD_PATRONI_PEER_PORT" >&2
      return 1
    fi
  done

  # Systemd unit
  cat > /etc/systemd/system/etcd-patroni.service <<UNIT_EOF
[Unit]
Description=etcd for Patroni DCS
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/etcd-patroni \\
  --name ${etcd_name} \\
  --data-dir /var/lib/etcd-patroni \\
  --listen-client-urls http://0.0.0.0:${client_port} \\
  --advertise-client-urls http://${advertise_ip}:${client_port} \\
  --listen-peer-urls http://0.0.0.0:${peer_port} \\
  --initial-advertise-peer-urls http://${advertise_ip}:${peer_port} \\
  --initial-cluster ${initial_cluster} \\
  --initial-cluster-state new \\
  --initial-cluster-token patroni-etcd
Restart=on-failure
RestartSec=5s
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT_EOF

  systemctl daemon-reload
  systemctl enable --now etcd-patroni

  # Wait for etcd to be healthy
  echo "[node1] waiting for etcd-patroni to start"
  for attempt in $(seq 1 30); do
    if ETCDCTL_API=3 /usr/local/bin/etcdctl-patroni \
      --endpoints="http://127.0.0.1:${client_port}" \
      endpoint health >/dev/null 2>&1; then
      echo "[node1] etcd-patroni healthy (attempt ${attempt})"
      return 0
    fi
    sleep 3
  done

  echo "[node1] etcd-patroni did not become healthy" >&2
  systemctl status etcd-patroni --no-pager || true
  journalctl -u etcd-patroni -n 30 --no-pager || true
  return 1
}

setup_etcd_patroni

beacon_status "complete" "Bootstrap complete" 100

echo "[node1] $(date -Is) complete"
