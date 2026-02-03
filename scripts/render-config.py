import argparse
import base64
import json
import os
import sys
from pathlib import Path

import yaml

REQUIRED_ROLES = ["bastion", "egress", "node1", "node2", "db"]


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text()) or {}


def load_json(path: Path):
    return json.loads(path.read_text())


def main() -> int:
    parser = argparse.ArgumentParser(description="Render config/infra.yaml into tofu.tfvars.json")
    parser.add_argument("--config", default="config/infra.yaml")
    parser.add_argument("--output", default="tofu/tofu.tfvars.json")
    parser.add_argument("--bootstrap-artifacts", default=None)
    args = parser.parse_args()

    config_path = Path(args.config)
    output_path = Path(args.output)

    config = load_yaml(config_path)

    project_slug = os.getenv("PROJECT_SLUG", "").strip()
    cloud_region = os.getenv("CLOUD_REGION", "").strip()
    environment = str(config.get("environment", "")).strip()
    runtime_environment = os.getenv("ENVIRONMENT", "").strip() or os.getenv("ENV", "").strip() or environment
    if project_slug:
        if environment:
            config["name_prefix"] = f"{project_slug}-{environment}"
        else:
            config["name_prefix"] = project_slug
    if cloud_region:
        config["location"] = cloud_region

    services = {svc.get("name") for svc in config.get("load_balancer", {}).get("services", [])}
    missing_services = [svc for svc in ("http", "https") if svc not in services]
    if missing_services:
        print(f"load_balancer.services must include: {', '.join(missing_services)}", file=sys.stderr)
        return 1

    ssh_keys_json = os.getenv("OPS_SSH_KEYS_JSON")
    if not ssh_keys_json:
        print("OPS_SSH_KEYS_JSON is required to render ssh_public_keys", file=sys.stderr)
        return 1
    try:
        raw_keys = json.loads(ssh_keys_json)
    except json.JSONDecodeError as exc:
        print(f"OPS_SSH_KEYS_JSON is not valid JSON: {exc}", file=sys.stderr)
        return 1

    ssh_public_keys = []
    if isinstance(raw_keys, dict):
        for value in raw_keys.values():
            if isinstance(value, list):
                ssh_public_keys.extend(value)
            elif isinstance(value, str):
                ssh_public_keys.append(value)
            else:
                print("OPS_SSH_KEYS_JSON values must be strings or lists of strings", file=sys.stderr)
                return 1
    elif isinstance(raw_keys, list):
        ssh_public_keys = raw_keys
    else:
        print("OPS_SSH_KEYS_JSON must be a map or list", file=sys.stderr)
        return 1

    ssh_public_keys = [key for key in ssh_public_keys if isinstance(key, str) and key.strip()]
    if not ssh_public_keys:
        print("OPS_SSH_KEYS_JSON did not contain any SSH public keys", file=sys.stderr)
        return 1

    config["ssh_public_keys"] = ssh_public_keys
    admin_users_json = json.dumps(raw_keys)
    config["admin_users_json_b64"] = base64.b64encode(admin_users_json.encode("utf-8")).decode("utf-8")

    missing_env = []
    errors = []

    def require_env(name: str) -> str:
        value = os.getenv(name, "").strip()
        if not value:
            missing_env.append(name)
        return value

    def optional_env(name: str) -> str:
        return os.getenv(name, "").strip()

    debug_root_password = optional_env("DEBUG_ROOT_PASSWORD")
    config["debug_root_password"] = debug_root_password

    def parse_int_env(name: str, minimum: int | None = None) -> int | None:
        raw = os.getenv(name, "").strip()
        if not raw:
            return None
        try:
            value = int(raw)
        except ValueError:
            errors.append(f"{name} must be an integer")
            return None
        if minimum is not None and value < minimum:
            errors.append(f"{name} must be >= {minimum}")
            return None
        return value

    def parse_json_env(name: str):
        raw = os.getenv(name, "").strip()
        if not raw:
            return None
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            errors.append(f"{name} is not valid JSON: {exc}")
            return None

    servers_cfg = config.get("servers", {})
    k3s_nodes = config.get("k3s_nodes")
    if not k3s_nodes:
        legacy_nodes = []
        for key in ("node1", "node2"):
            node = servers_cfg.get(key)
            if node:
                legacy_nodes.append(node)
        if legacy_nodes:
            k3s_nodes = legacy_nodes

    if not isinstance(k3s_nodes, list):
        errors.append("k3s_nodes must be a list")
        k3s_nodes = []

    k3s_node_count = parse_int_env("K3S_NODE_COUNT", minimum=1)
    if k3s_node_count is None:
        k3s_node_count = len(k3s_nodes)

    if k3s_node_count < 1:
        errors.append("K3S_NODE_COUNT must be >= 1")
    if len(k3s_nodes) < k3s_node_count:
        errors.append("k3s_nodes must include at least K3S_NODE_COUNT entries")

    config["k3s_nodes"] = k3s_nodes[:k3s_node_count]

    k3s_node_cidrs = []
    for node in config["k3s_nodes"]:
        ip = str(node.get("private_ip", "")).strip()
        if ip:
            k3s_node_cidrs.append(f"{ip}/32")

    k3s_cfg = config.get("k3s", {}) or {}
    k3s_token_name = str(k3s_cfg.get("token_name", "")).strip()
    if not k3s_token_name:
        k3s_token_name = "K3S_TOKEN"
    k3s_token = os.getenv(k3s_token_name, "").strip()
    if not k3s_token:
        k3s_token = os.getenv(k3s_token_name.upper(), "").strip()
    if not k3s_token:
        k3s_token = os.getenv("K3S_TOKEN", "").strip()
    if not k3s_token:
        missing_env.append(k3s_token_name)

    k3s_server_private_ip = ""
    if config["k3s_nodes"]:
        k3s_server_private_ip = str(config["k3s_nodes"][0].get("private_ip", "")).strip()
    if not k3s_server_private_ip:
        errors.append("k3s_nodes[0].private_ip is required for k3s server")

    s3_access_key = os.getenv("S3_ACCESS_KEY_ID") or os.getenv("AWS_ACCESS_KEY_ID", "")
    s3_secret_key = os.getenv("S3_SECRET_ACCESS_KEY") or os.getenv("AWS_SECRET_ACCESS_KEY", "")
    s3_endpoint = os.getenv("S3_ENDPOINT", "").strip()
    s3_region = (
        os.getenv("S3_REGION")
        or os.getenv("AWS_REGION")
        or os.getenv("AWS_DEFAULT_REGION")
        or os.getenv("CLOUD_REGION")
        or "us-east-1"
    )

    if not s3_access_key:
        missing_env.append("S3_ACCESS_KEY_ID")
    if not s3_secret_key:
        missing_env.append("S3_SECRET_ACCESS_KEY")
    if not s3_endpoint:
        missing_env.append("S3_ENDPOINT")

    bastion_server_type = require_env("BASTION_SERVER_TYPE")
    egress_server_type = require_env("EGRESS_SERVER_TYPE")
    db_server_type = require_env("DB_SERVER_TYPE")
    k3s_node_server_type = require_env("K3S_NODE_SERVER_TYPE")

    db_type = require_env("DB_TYPE")
    db_version = require_env("DB_VERSION")
    app_db_name = require_env("APP_DB_NAME")
    app_db_user = require_env("APP_DB_USER")
    app_db_password = require_env("APP_DB_PASSWORD")
    if db_type and db_type.lower() not in ("postgresql", "postgres"):
        errors.append("DB_TYPE must be 'postgresql'")
    if db_version and db_version != "14.20":
        errors.append("DB_VERSION must be '14.20'")

    infisical_restore_from_s3 = os.getenv("INFISICAL_RESTORE_FROM_S3", "").strip()
    if not infisical_restore_from_s3:
        infisical_restore_from_s3 = "false"
    restore_requested = infisical_restore_from_s3.lower() == "true"

    infisical_project_name = require_env("INFISICAL_PROJECT_NAME")

    infisical_bootstrap_secrets_raw = os.getenv("INFISICAL_BOOTSTRAP_SECRETS", "").strip()
    infisical_bootstrap_secrets = ""
    if infisical_bootstrap_secrets_raw:
        try:
            parsed_bootstrap_secrets = json.loads(infisical_bootstrap_secrets_raw)
        except json.JSONDecodeError as exc:
            errors.append(f"INFISICAL_BOOTSTRAP_SECRETS is not valid JSON: {exc}")
        else:
            if not isinstance(parsed_bootstrap_secrets, dict):
                errors.append("INFISICAL_BOOTSTRAP_SECRETS must be a JSON object")
            else:
                infisical_bootstrap_secrets = json.dumps(parsed_bootstrap_secrets)

    if restore_requested:
        db_backup_age_private_key = require_env("DB_BACKUP_AGE_PRIVATE_KEY")
    else:
        db_backup_age_private_key = os.getenv("DB_BACKUP_AGE_PRIVATE_KEY", "").strip()

    egress_secrets = {
        "S3_ACCESS_KEY_ID": s3_access_key,
        "S3_SECRET_ACCESS_KEY": s3_secret_key,
        "S3_ENDPOINT": s3_endpoint,
        "S3_REGION": s3_region,
        "DB_BACKUP_BUCKET": require_env("DB_BACKUP_BUCKET"),
        "DB_BACKUP_AGE_PUBLIC_KEY": require_env("DB_BACKUP_AGE_PUBLIC_KEY"),
        "INFISICAL_RESTORE_FROM_S3": infisical_restore_from_s3.lower(),
        "INFISICAL_PASSWORD": require_env("INFISICAL_PASSWORD"),
        "INFISICAL_EMAIL": require_env("INFISICAL_EMAIL"),
        "INFISICAL_ORGANIZATION": require_env("INFISICAL_ORGANIZATION"),
        "INFISICAL_NAME": require_env("INFISICAL_NAME"),
        "INFISICAL_SURNAME": require_env("INFISICAL_SURNAME"),
        "INFISICAL_PROJECT_NAME": infisical_project_name,
        "INFISICAL_POSTGRES_DB": require_env("INFISICAL_POSTGRES_DB"),
        "INFISICAL_POSTGRES_USER": require_env("INFISICAL_POSTGRES_USER"),
        "INFISICAL_POSTGRES_PASSWORD": require_env("INFISICAL_POSTGRES_PASSWORD"),
        "INFISICAL_ENCRYPTION_KEY": require_env("INFISICAL_ENCRYPTION_KEY"),
        "INFISICAL_AUTH_SECRET": require_env("INFISICAL_AUTH_SECRET"),
    }

    db_secrets = {
        "DB_TYPE": db_type,
        "DB_VERSION": db_version,
        "APP_DB_NAME": app_db_name,
        "APP_DB_USER": app_db_user,
        "APP_DB_PASSWORD": app_db_password,
        "S3_ACCESS_KEY_ID": s3_access_key,
        "S3_SECRET_ACCESS_KEY": s3_secret_key,
        "S3_ENDPOINT": s3_endpoint,
        "S3_REGION": s3_region,
        "DB_BACKUP_BUCKET": require_env("DB_BACKUP_BUCKET"),
        "DB_BACKUP_AGE_PUBLIC_KEY": require_env("DB_BACKUP_AGE_PUBLIC_KEY"),
        "K3S_NODE_CIDRS": ",".join(k3s_node_cidrs),
    }

    infisical_site_url = os.getenv("INFISICAL_SITE_URL", "").strip()
    if infisical_site_url:
        egress_secrets["INFISICAL_SITE_URL"] = infisical_site_url

    if infisical_bootstrap_secrets:
        egress_secrets["INFISICAL_BOOTSTRAP_SECRETS"] = infisical_bootstrap_secrets

    internal_services = {}
    internal_services_json = parse_json_env("INTERNAL_SERVICES_DOMAINS_JSON")
    required_service_keys = ("bastion", "grafana", "loki", "infisical", "db")
    optional_service_keys = ("argocd", "kubernetes")
    if internal_services_json is not None:
        if not isinstance(internal_services_json, dict):
            errors.append("INTERNAL_SERVICES_DOMAINS_JSON must be a JSON object")
        else:
            missing_keys = [key for key in required_service_keys if key not in internal_services_json]
            if missing_keys:
                errors.append(f"INTERNAL_SERVICES_DOMAINS_JSON missing keys: {', '.join(missing_keys)}")
            for key in (*required_service_keys, *optional_service_keys):
                if key not in internal_services_json:
                    continue
                value = internal_services_json.get(key)
                if not isinstance(value, dict):
                    errors.append(f"INTERNAL_SERVICES_DOMAINS_JSON.{key} must be an object with fqdn")
                    continue
                fqdn = str(value.get("fqdn", "")).strip()
                if not fqdn:
                    errors.append(f"INTERNAL_SERVICES_DOMAINS_JSON.{key}.fqdn is required")
                    continue
                internal_services[key] = fqdn
    else:
        env_map = {
            "bastion": "BASTION_FQDN",
            "grafana": "GRAFANA_FQDN",
            "loki": "LOKI_FQDN",
            "infisical": "INFISICAL_FQDN",
            "db": "DB_FQDN",
            "argocd": "ARGOCD_FQDN",
            "kubernetes": "KUBERNETES_FQDN",
        }
        for key, env_name in env_map.items():
            fqdn = optional_env(env_name)
            if fqdn:
                internal_services[key] = fqdn

    deployed_apps = []
    deployed_apps_json = parse_json_env("DEPLOYED_APPS_JSON")
    if deployed_apps_json is not None:
        if not isinstance(deployed_apps_json, list):
            errors.append("DEPLOYED_APPS_JSON must be a JSON array")
        else:
            for idx, app in enumerate(deployed_apps_json):
                if not isinstance(app, dict):
                    errors.append(f"DEPLOYED_APPS_JSON[{idx}] must be an object")
                    continue
                fqdn = str(app.get("fqdn", "")).strip()
                if not fqdn:
                    errors.append(f"DEPLOYED_APPS_JSON[{idx}].fqdn is required")
                    continue
                deployed_apps.append(app)

    cloudflare_api_token = optional_env("CLOUDFLARE_API_TOKEN")
    if (internal_services or deployed_apps) and not cloudflare_api_token:
        missing_env.append("CLOUDFLARE_API_TOKEN")

    if cloudflare_api_token:
        egress_secrets["CLOUDFLARE_API_TOKEN"] = cloudflare_api_token

    infisical_fqdn = internal_services.get("infisical", "")
    grafana_fqdn = internal_services.get("grafana", "")
    loki_fqdn = internal_services.get("loki", "")
    argocd_fqdn = internal_services.get("argocd", "")
    kubernetes_fqdn = internal_services.get("kubernetes", "")
    db_fqdn = internal_services.get("db", "")
    if infisical_fqdn:
        egress_secrets["INFISICAL_FQDN"] = infisical_fqdn
    if grafana_fqdn:
        egress_secrets["GRAFANA_FQDN"] = grafana_fqdn
    if loki_fqdn:
        egress_secrets["LOKI_FQDN"] = loki_fqdn
    if argocd_fqdn:
        egress_secrets["ARGOCD_FQDN"] = argocd_fqdn
    if kubernetes_fqdn:
        egress_secrets["KUBERNETES_FQDN"] = kubernetes_fqdn
    if k3s_server_private_ip:
        egress_secrets["K3S_SERVER_PRIVATE_IP"] = k3s_server_private_ip
    if not infisical_site_url and infisical_fqdn:
        infisical_site_url = f"https://{infisical_fqdn}"
        egress_secrets["INFISICAL_SITE_URL"] = infisical_site_url

    if db_fqdn:
        db_secrets["DB_FQDN"] = db_fqdn
    if cloudflare_api_token:
        db_secrets["CLOUDFLARE_API_TOKEN"] = cloudflare_api_token
    if egress_secrets.get("INFISICAL_EMAIL"):
        db_secrets["INFISICAL_EMAIL"] = egress_secrets.get("INFISICAL_EMAIL", "")

    if project_slug:
        egress_secrets["PROJECT_SLUG"] = project_slug
    if runtime_environment:
        egress_secrets["ENVIRONMENT"] = runtime_environment

    wg_server_address = require_env("WG_SERVER_ADDRESS")

    bastion_secrets = {
        "WG_SERVER_PRIVATE_KEY": require_env("WG_SERVER_PRIVATE_KEY"),
        "WG_SERVER_PUBLIC_KEY": require_env("WG_SERVER_PUBLIC_KEY"),
        "WG_SERVER_ADDRESS": wg_server_address,
        "WG_LISTEN_PORT": require_env("WG_LISTEN_PORT"),
        "WG_ADMIN_PEERS_JSON": require_env("WG_ADMIN_PEERS_JSON"),
        "WG_PRESHARED_KEYS_JSON": require_env("WG_PRESHARED_KEYS_JSON"),
    }

    gh_token = optional_env("GH_TOKEN")
    gh_owner = optional_env("GH_OWNER")
    gh_infra_repo = optional_env("GH_INFRA_REPO")
    gh_gitops_repo = optional_env("GH_GITOPS_REPO")

    def resolve_repo_url(repo: str, owner: str) -> tuple[str, list[str]]:
        if not repo:
            return "", []
        repo = repo.strip()
        if repo.startswith("http://") or repo.startswith("https://"):
            return repo, []
        if "/" in repo:
            repo_ref = repo
        else:
            if not owner:
                return "", ["GH_OWNER is required when GH_GITOPS_REPO is not owner/repo"]
            repo_ref = f"{owner}/{repo}"
        if repo_ref.endswith(".git"):
            return f"https://github.com/{repo_ref}", []
        return f"https://github.com/{repo_ref}.git", []

    argocd_cfg = config.get("argocd", {}) or {}
    argocd_repo_path = str(argocd_cfg.get("repo_path", "")).strip()
    argocd_repo_revision = str(argocd_cfg.get("repo_revision", "")).strip() or "main"
    argocd_app_name = str(argocd_cfg.get("app_name", "")).strip() or "root"
    argocd_app_project = str(argocd_cfg.get("app_project", "")).strip() or "default"
    argocd_dest_namespace = str(argocd_cfg.get("destination_namespace", "")).strip() or "argocd"
    argocd_dest_server = str(argocd_cfg.get("destination_server", "")).strip() or "https://kubernetes.default.svc"

    argocd_repo_url, repo_errors = resolve_repo_url(gh_gitops_repo, gh_owner)
    if repo_errors:
        errors.extend(repo_errors)

    argocd_enabled = bool(argocd_repo_path and argocd_repo_url)
    if argocd_repo_path and not gh_gitops_repo:
        missing_env.append("GH_GITOPS_REPO")
    if gh_gitops_repo and not argocd_repo_path:
        errors.append("argocd.repo_path is required when GH_GITOPS_REPO is set")

    argocd_admin_password = optional_env("ARGOCD_ADMIN_PASSWORD")
    if argocd_enabled and not argocd_admin_password:
        missing_env.append("ARGOCD_ADMIN_PASSWORD")
    if argocd_enabled and not gh_token:
        missing_env.append("GH_TOKEN")

    egress_private_ip = str(servers_cfg.get("egress", {}).get("private_ip", "")).strip()
    k3s_secrets = {
        "K3S_TOKEN": k3s_token,
        "K3S_SERVER_IP": k3s_server_private_ip,
        "K3S_SERVER_URL": f"https://{k3s_server_private_ip}:6443" if k3s_server_private_ip else "",
        "K3S_SERVER_TAINT": str(bool(k3s_cfg.get("server_taint", False))).lower(),
        "EGRESS_LOKI_URL": f"http://{egress_private_ip}:3100/loki/api/v1/push" if egress_private_ip else "",
    }

    k3s_server_secrets = {}
    k3s_agent_secrets = {}

    if argocd_admin_password:
        k3s_server_secrets["ARGOCD_ADMIN_PASSWORD"] = argocd_admin_password
    if gh_token:
        k3s_server_secrets["GH_TOKEN"] = gh_token
    if argocd_fqdn:
        k3s_server_secrets["ARGOCD_FQDN"] = argocd_fqdn
    if argocd_enabled:
        k3s_server_secrets.update(
            {
                "ARGOCD_APP_REPO_URL": argocd_repo_url,
                "ARGOCD_APP_PATH": argocd_repo_path,
                "ARGOCD_APP_REVISION": argocd_repo_revision,
                "ARGOCD_APP_NAME": argocd_app_name,
                "ARGOCD_APP_PROJECT": argocd_app_project,
                "ARGOCD_APP_DEST_NAMESPACE": argocd_dest_namespace,
                "ARGOCD_APP_DEST_SERVER": argocd_dest_server,
            }
        )

    if infisical_fqdn:
        k3s_server_secrets["INFISICAL_FQDN"] = infisical_fqdn
    if infisical_site_url:
        k3s_server_secrets["INFISICAL_SITE_URL"] = infisical_site_url
    if kubernetes_fqdn:
        k3s_server_secrets["KUBERNETES_FQDN"] = kubernetes_fqdn
    k3s_server_secrets.update(
        {
            "INFISICAL_PASSWORD": egress_secrets.get("INFISICAL_PASSWORD", ""),
            "INFISICAL_EMAIL": egress_secrets.get("INFISICAL_EMAIL", ""),
            "INFISICAL_ORGANIZATION": egress_secrets.get("INFISICAL_ORGANIZATION", ""),
            "INFISICAL_NAME": egress_secrets.get("INFISICAL_NAME", ""),
            "INFISICAL_SURNAME": egress_secrets.get("INFISICAL_SURNAME", ""),
        }
    )
    k3s_server_secrets.update(
        {
            "S3_ACCESS_KEY_ID": s3_access_key,
            "S3_SECRET_ACCESS_KEY": s3_secret_key,
            "S3_ENDPOINT": s3_endpoint,
            "S3_REGION": s3_region,
            "DB_BACKUP_BUCKET": egress_secrets.get("DB_BACKUP_BUCKET", ""),
            "DB_BACKUP_AGE_PUBLIC_KEY": egress_secrets.get("DB_BACKUP_AGE_PUBLIC_KEY", ""),
            "DB_BACKUP_AGE_PRIVATE_KEY": require_env("DB_BACKUP_AGE_PRIVATE_KEY"),
            "INFISICAL_RESTORE_FROM_S3": infisical_restore_from_s3.lower(),
        }
    )
    if infisical_bootstrap_secrets:
        k3s_server_secrets["INFISICAL_BOOTSTRAP_SECRETS"] = infisical_bootstrap_secrets
    if project_slug:
        k3s_server_secrets["PROJECT_SLUG"] = project_slug
    if runtime_environment:
        k3s_server_secrets["ENVIRONMENT"] = runtime_environment
    if infisical_project_name:
        k3s_server_secrets["INFISICAL_PROJECT_NAME"] = infisical_project_name

    config["bastion_server_type"] = bastion_server_type
    config["egress_server_type"] = egress_server_type
    config["db_server_type"] = db_server_type
    config["k3s_node_server_type"] = k3s_node_server_type
    config["internal_services_domains"] = {key: {"fqdn": value} for key, value in internal_services.items()}
    config["deployed_apps"] = deployed_apps

    if errors:
        print("Config rendering failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1

    if missing_env:
        missing_env = sorted(set(missing_env))
        print(f"Missing required environment variables for bootstrap: {', '.join(missing_env)}", file=sys.stderr)
        return 1

    config["egress_secrets"] = egress_secrets
    config["bastion_secrets"] = bastion_secrets
    config["db_secrets"] = db_secrets
    config["k3s_secrets"] = k3s_secrets
    config["k3s_server_secrets"] = k3s_server_secrets
    config["k3s_agent_secrets"] = k3s_agent_secrets
    config["db_backup_age_private_key"] = db_backup_age_private_key
    config["wg_server_address"] = wg_server_address

    if args.bootstrap_artifacts:
        artifacts = load_json(Path(args.bootstrap_artifacts))
        missing = [role for role in REQUIRED_ROLES if role not in artifacts]
        if missing:
            print(f"Missing bootstrap artifacts for roles: {', '.join(missing)}", file=sys.stderr)
            return 1
        config["bootstrap_artifacts"] = artifacts
    else:
        config["bootstrap_artifacts"] = {}

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(config, indent=2))
    print(f"Rendered {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
