#!/usr/bin/env bash
set -euo pipefail

LOG_FILE="/var/log/infrazero-bootstrap.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[node1] $(date -Is) start"

ENV_FILE="/etc/infrazero/node1.env"
if [ -f "$ENV_FILE" ]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "[node1] missing required env: $name" >&2
    exit 1
  fi
}

require_env "EGRESS_LOKI_URL"

if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y curl jq age unzip apache2-utils
fi

if ! command -v aws >/dev/null 2>&1; then
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o /tmp/awscliv2.zip
  unzip -q /tmp/awscliv2.zip -d /tmp
  /tmp/aws/install --bin-dir /usr/local/bin --install-dir /usr/local/aws-cli --update
fi

install_k3s() {
  if systemctl is-active --quiet k3s; then
    echo "[node1] k3s already running"
    return 0
  fi
  curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server --write-kubeconfig-mode 644" sh -
}

wait_for_k3s() {
  export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
  for i in {1..60}; do
    if kubectl get nodes >/dev/null 2>&1; then
      if kubectl get nodes --no-headers 2>/dev/null | awk '$2=="Ready" {print $1}' | grep -q .; then
        echo "[node1] k3s node ready"
        return 0
      fi
    fi
    sleep 2
  done
  echo "[node1] k3s did not become ready in time" >&2
  return 1
}

ensure_nodeports() {
  if ! kubectl -n kube-system get svc traefik >/dev/null 2>&1; then
    echo "[node1] traefik service not found; skipping NodePort patch"
    return 0
  fi
  kubectl -n kube-system patch svc traefik --type merge -p '{
    "spec": {
      "type": "NodePort",
      "ports": [
        {"name":"web","port":80,"protocol":"TCP","targetPort":8000,"nodePort":30080},
        {"name":"websecure","port":443,"protocol":"TCP","targetPort":8443,"nodePort":30443}
      ]
    }
  }' >/dev/null
  echo "[node1] ensured NodePorts 30080/30443"
}

publish_k3s_token() {
  require_env "S3_ACCESS_KEY_ID"
  require_env "S3_SECRET_ACCESS_KEY"
  require_env "S3_ENDPOINT"
  require_env "S3_REGION"
  require_env "INFRA_STATE_BUCKET"
  require_env "K3S_TOKEN_NAME"

  export AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY_ID"
  export AWS_SECRET_ACCESS_KEY="$S3_SECRET_ACCESS_KEY"
  export AWS_DEFAULT_REGION="$S3_REGION"

  local token_file="/var/lib/rancher/k3s/server/node-token"
  if [ ! -s "$token_file" ]; then
    echo "[node1] k3s token file not found at ${token_file}" >&2
    return 1
  fi

  local prefix="${STATE_PREFIX:-}"
  prefix="${prefix#/}"
  prefix="${prefix%/}"
  local key
  if [ -n "$prefix" ]; then
    key="k3s/${prefix}/${K3S_TOKEN_NAME}"
  else
    key="k3s/${K3S_TOKEN_NAME}"
  fi

  aws --endpoint-url "$S3_ENDPOINT" s3 cp "$token_file" "s3://${INFRA_STATE_BUCKET}/${key}" >/dev/null
  echo "[node1] published k3s token to s3://${INFRA_STATE_BUCKET}/${key}"
}

install_k3s
wait_for_k3s
ensure_nodeports
publish_k3s_token

install_argocd() {
  if ! kubectl get ns argocd >/dev/null 2>&1; then
    kubectl create ns argocd
  fi

  local version="${ARGOCD_VERSION:-v2.11.7}"
  local url="https://raw.githubusercontent.com/argoproj/argo-cd/${version}/manifests/install.yaml"
  curl -fsSL "$url" | kubectl apply -n argocd -f -

  kubectl -n argocd rollout status deployment/argocd-server --timeout=300s
}

configure_argocd() {
  require_env "ARGOCD_ADMIN_PASSWORD"

  local mtime
  mtime=$(date -u +%FT%TZ)
  local hash
  hash=$(htpasswd -bnBC 10 "" "$ARGOCD_ADMIN_PASSWORD" | tr -d ':\n')

  kubectl -n argocd patch secret argocd-secret --type merge -p "$(jq -n --arg pwd "$hash" --arg mt "$mtime" '{stringData: {"admin.password": $pwd, "admin.passwordMtime": $mt}}')"

  kubectl -n argocd apply -f - <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: argocd-cmd-params-cm
  namespace: argocd
data:
  server.insecure: "true"
EOF

  kubectl -n argocd rollout restart deployment/argocd-server
  kubectl -n argocd rollout status deployment/argocd-server --timeout=300s
}

install_cert_manager() {
  if kubectl get crd clusterissuers.cert-manager.io >/dev/null 2>&1; then
    return 0
  fi
  local version="${CERT_MANAGER_VERSION:-v1.14.4}"
  local url="https://github.com/cert-manager/cert-manager/releases/download/${version}/cert-manager.yaml"
  kubectl apply -f "$url"
  kubectl -n cert-manager rollout status deployment/cert-manager --timeout=300s
  kubectl -n cert-manager rollout status deployment/cert-manager-webhook --timeout=300s
  kubectl -n cert-manager rollout status deployment/cert-manager-cainjector --timeout=300s
}

configure_argocd_ingress() {
  if [ -z "${ARGOCD_FQDN:-}" ]; then
    echo "[node1] ARGOCD_FQDN not set; skipping ingress"
    return 0
  fi

  require_env "CLOUDFLARE_API_TOKEN"
  local le_email="${LETSENCRYPT_EMAIL:-${INFISICAL_EMAIL:-}}"
  if [ -z "$le_email" ]; then
    echo "[node1] LETSENCRYPT_EMAIL or INFISICAL_EMAIL required for cert-manager" >&2
    return 1
  fi

  install_cert_manager

  kubectl -n cert-manager create secret generic cloudflare-api-token \
    --from-literal=api-token="$CLOUDFLARE_API_TOKEN" \
    --dry-run=client -o yaml | kubectl apply -f -

  kubectl apply -f - <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-cloudflare
spec:
  acme:
    email: ${le_email}
    server: https://acme-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: letsencrypt-cloudflare
    solvers:
      - dns01:
          cloudflare:
            apiTokenSecretRef:
              name: cloudflare-api-token
              key: api-token
EOF

  kubectl -n argocd apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: argocd-server
  namespace: argocd
  annotations:
    kubernetes.io/ingress.class: traefik
    traefik.ingress.kubernetes.io/router.entrypoints: web,websecure
    traefik.ingress.kubernetes.io/router.tls: "true"
    cert-manager.io/cluster-issuer: letsencrypt-cloudflare
spec:
  tls:
    - hosts:
        - ${ARGOCD_FQDN}
      secretName: argocd-tls
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
}

bootstrap_argocd_app() {
  if [ -z "${ARGOCD_APP_REPO:-}" ] || [ -z "${ARGOCD_APP_PATH:-}" ]; then
    echo "[node1] Argo CD app bootstrap skipped (missing ARGOCD_APP_REPO or ARGOCD_APP_PATH)"
    return 0
  fi

  if [ -n "${GH_TOKEN:-}" ]; then
    local repo_name
    repo_name=$(echo "$ARGOCD_APP_REPO" | tr -cs '[:alnum:]' '-' | sed 's/^-//;s/-$//')
    local repo_user="x-access-token"
    kubectl -n argocd apply -f - <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: repo-${repo_name}
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  url: ${ARGOCD_APP_REPO}
  username: ${repo_user}
  password: ${GH_TOKEN}
EOF
  fi

  local app_name="${ARGOCD_APP_NAME:-root-app}"
  local app_project="${ARGOCD_APP_PROJECT:-default}"
  local app_revision="${ARGOCD_APP_REVISION:-main}"
  local dest_namespace="${ARGOCD_APP_DEST_NAMESPACE:-default}"

  kubectl -n argocd apply -f - <<EOF
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: ${app_name}
  namespace: argocd
spec:
  project: ${app_project}
  source:
    repoURL: ${ARGOCD_APP_REPO}
    path: ${ARGOCD_APP_PATH}
    targetRevision: ${app_revision}
  destination:
    server: https://kubernetes.default.svc
    namespace: ${dest_namespace}
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
EOF
}

install_argocd
configure_argocd
configure_argocd_ingress
bootstrap_argocd_app

setup_promtail() {
  if [ ! -f /usr/local/bin/promtail ]; then
    curl -fsSL -o /tmp/promtail.zip "https://github.com/grafana/loki/releases/download/v2.9.3/promtail-linux-amd64.zip"
    unzip -o /tmp/promtail.zip -d /usr/local/bin
    mv /usr/local/bin/promtail-linux-amd64 /usr/local/bin/promtail
    chmod +x /usr/local/bin/promtail
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
  - job_name: systemd-journal
    journal:
      max_age: 12h
      labels:
        job: systemd-journal
    relabel_configs:
      - source_labels: ["__journal__systemd_unit"]
        target_label: unit
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
}

setup_promtail

wait_for_infisical() {
  local url="$1"
  for i in {1..60}; do
    local code
    code=$(curl -sk -o /dev/null -w "%{http_code}" "$url" || true)
    if [ -n "$code" ] && [ "$code" != "000" ]; then
      return 0
    fi
    sleep 5
  done
  return 1
}

s3_has_infisical_backup() {
  local tmpdir="$1"
  local manifest="${tmpdir}/latest-dump.json"
  if ! aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://${DB_BACKUP_BUCKET}/infisical/latest-dump.json" "$manifest" >/dev/null 2>&1; then
    return 1
  fi
  local key
  key=$(jq -r '.key // empty' "$manifest")
  if [ -z "$key" ] || [ "$key" = "null" ]; then
    return 1
  fi
  if aws --endpoint-url "$S3_ENDPOINT" s3 ls "s3://${DB_BACKUP_BUCKET}/${key}" >/dev/null 2>&1; then
    return 0
  fi
  return 1
}

store_token_encrypted() {
  local token="$1"
  local key_name="$2"
  local tmpdir="$3"
  local plain="${tmpdir}/token.txt"
  local enc="${tmpdir}/token.txt.age"

  printf '%s' "$token" > "$plain"
  age -r "$DB_BACKUP_AGE_PUBLIC_KEY" -o "$enc" "$plain"
  local sha
  sha=$(sha256sum "$enc" | awk '{print $1}')
  aws --endpoint-url "$S3_ENDPOINT" s3 cp "$enc" "s3://${DB_BACKUP_BUCKET}/${key_name}" >/dev/null
  rm -f "$plain" "$enc"
  echo "$sha"
}

update_manifest_tokens() {
  local admin_key="$1"
  local admin_sha="$2"
  local admin_time="$3"
  local ro_key="$4"
  local ro_sha="$5"
  local ro_time="$6"
  local tmpdir="$7"

  local manifest="${tmpdir}/latest-dump.json"
  if ! aws --endpoint-url "$S3_ENDPOINT" s3 cp "s3://${DB_BACKUP_BUCKET}/infisical/latest-dump.json" "$manifest" >/dev/null 2>&1; then
    echo "[node1] latest-dump manifest not found; skipping token metadata update"
    return 0
  fi

  jq --arg admin_key "$admin_key" \
     --arg admin_sha "$admin_sha" \
     --arg admin_time "$admin_time" \
     --arg ro_key "$ro_key" \
     --arg ro_sha "$ro_sha" \
     --arg ro_time "$ro_time" \
     '.tokens = (.tokens // {}) |
      .tokens.admin = {key: $admin_key, sha256: $admin_sha, created_at: $admin_time} |
      .tokens.read_only = {key: $ro_key, sha256: $ro_sha, created_at: $ro_time}' \
     "$manifest" > "${manifest}.new"

  aws --endpoint-url "$S3_ENDPOINT" s3 cp "${manifest}.new" "s3://${DB_BACKUP_BUCKET}/infisical/latest-dump.json" >/dev/null
}

bootstrap_infisical() {
  require_env "S3_ACCESS_KEY_ID"
  require_env "S3_SECRET_ACCESS_KEY"
  require_env "S3_ENDPOINT"
  require_env "S3_REGION"
  require_env "DB_BACKUP_BUCKET"
  require_env "DB_BACKUP_AGE_PUBLIC_KEY"
  require_env "INFISICAL_EMAIL"
  require_env "INFISICAL_PASSWORD"
  require_env "INFISICAL_ORGANIZATION"
  require_env "INFISICAL_FQDN"

  export AWS_ACCESS_KEY_ID="$S3_ACCESS_KEY_ID"
  export AWS_SECRET_ACCESS_KEY="$S3_SECRET_ACCESS_KEY"
  export AWS_DEFAULT_REGION="$S3_REGION"

  local base_url="https://${INFISICAL_FQDN}"
  echo "[node1] waiting for Infisical at $base_url"
  if ! wait_for_infisical "${base_url}/api/v1/admin/bootstrap"; then
    echo "[node1] Infisical did not become reachable in time" >&2
    return 1
  fi

  local tmpdir
  tmpdir=$(mktemp -d /run/infrazero-infisical.XXXX)
  chmod 700 "$tmpdir"

  local restore_flag="${INFISICAL_RESTORE_FROM_S3:-false}"
  if [ "${restore_flag,,}" = "true" ] && s3_has_infisical_backup "$tmpdir"; then
    echo "[node1] infisical_restore_from_s3=true and backup present; skipping bootstrap"
    rm -rf "$tmpdir"
    return 0
  fi

  local payload
  payload=$(jq -n --arg email "$INFISICAL_EMAIL" --arg password "$INFISICAL_PASSWORD" --arg org "$INFISICAL_ORGANIZATION" \
    '{email: $email, password: $password, organization: $org}')

  local resp_file="${tmpdir}/bootstrap.json"
  local http_code
  http_code=$(curl -sk -o "$resp_file" -w "%{http_code}" -H "Content-Type: application/json" -d "$payload" \
    "${base_url}/api/v1/admin/bootstrap" || true)

  if [ "$http_code" -lt 200 ] || [ "$http_code" -ge 300 ]; then
    if grep -qi "bootstrapp" "$resp_file"; then
      echo "[node1] infisical already bootstrapped; skipping"
      rm -rf "$tmpdir"
      return 0
    fi
    echo "[node1] infisical bootstrap failed (status ${http_code})" >&2
    cat "$resp_file" >&2 || true
    rm -rf "$tmpdir"
    return 1
  fi

  local admin_token
  admin_token=$(jq -r '.identity.credentials.token // empty' "$resp_file")
  local org_id
  org_id=$(jq -r '.organization.id // empty' "$resp_file")
  if [ -z "$admin_token" ] || [ -z "$org_id" ]; then
    echo "[node1] missing admin token or organization id in bootstrap response" >&2
    rm -rf "$tmpdir"
    return 1
  fi

  local timestamp
  timestamp=$(date -u +%Y%m%dT%H%M%SZ)
  local created_at
  created_at=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  local admin_key="infisical/tokens/admin-${timestamp}.token.age"
  local admin_sha
  admin_sha=$(store_token_encrypted "$admin_token" "$admin_key" "$tmpdir")

  local readonly_identity_name="infrazero-readonly"
  local identity_id
  identity_id=$(curl -sk -H "Authorization: Bearer ${admin_token}" -H "Content-Type: application/json" \
    -d "$(jq -n --arg name "$readonly_identity_name" '{limit: 1, offset: 0, search: {name: $name}}')" \
    "${base_url}/api/v1/identities/search" | jq -r '.identities[0].identity.id // empty')

  if [ -z "$identity_id" ]; then
    identity_id=$(curl -sk -H "Authorization: Bearer ${admin_token}" -H "Content-Type: application/json" \
      -d "$(jq -n --arg name "$readonly_identity_name" --arg org "$org_id" '{name: $name, organizationId: $org, role: "member", hasDeleteProtection: false}')" \
      "${base_url}/api/v1/identities" | jq -r '.identity.id // empty')
  fi

  if [ -z "$identity_id" ]; then
    echo "[node1] unable to create/read read-only identity" >&2
    rm -rf "$tmpdir"
    return 1
  fi

  local ro_token
  ro_token=$(curl -sk -H "Authorization: Bearer ${admin_token}" -H "Content-Type: application/json" \
    -d "$(jq -n --arg name "bootstrap-readonly-${timestamp}" '{name: $name}')" \
    "${base_url}/api/v1/auth/token-auth/identities/${identity_id}/tokens" | jq -r '.accessToken // empty')

  if [ -z "$ro_token" ]; then
    echo "[node1] failed to create read-only token" >&2
    rm -rf "$tmpdir"
    return 1
  fi

  local ro_key="infisical/tokens/readonly-${timestamp}.token.age"
  local ro_sha
  ro_sha=$(store_token_encrypted "$ro_token" "$ro_key" "$tmpdir")

  kubectl -n kube-system create secret generic infisical-readonly-token \
    --from-literal=token="$ro_token" \
    --dry-run=client -o yaml | kubectl apply -f -

  update_manifest_tokens "$admin_key" "$admin_sha" "$created_at" "$ro_key" "$ro_sha" "$created_at" "$tmpdir"
  rm -rf "$tmpdir"
  echo "[node1] infisical bootstrap complete"
}

bootstrap_infisical

echo "[node1] $(date -Is) complete"
