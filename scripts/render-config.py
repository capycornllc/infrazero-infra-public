import argparse
import base64
import gzip
import hashlib
import ipaddress
import json
import os
import re
import sys
from pathlib import Path

import yaml

REQUIRED_ROLES = ["bastion", "egress", "node1", "nodecp", "node2", "db"]


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text()) or {}


def load_json(path: Path):
    # utf-8-sig allows JSON files written with a UTF-8 BOM (common on Windows).
    return json.loads(path.read_text(encoding="utf-8-sig"))


def parse_ipv4_cidrs_and_wildcards(raw: str, label: str) -> tuple[list[str], list[str]]:
    """Parse comma-separated IPv4 CIDRs and wildcard IPv4 last-octet prefixes.

    Wildcard format:
      - 10.10.0.2*  -> matches 10.10.0.20-10.10.0.29 (collapsed to CIDRs)
      - 10.10.0.*   -> matches the full /24
    """
    out: list[str] = []
    errors: list[str] = []
    seen: set[str] = set()

    def add(cidr: str):
        if cidr not in seen:
            seen.add(cidr)
            out.append(cidr)

    tokens = [token.strip() for token in raw.split(",") if token.strip()]
    for token in tokens:
        if "*" in token:
            match = re.fullmatch(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.)(\d{0,2})\*", token)
            if not match:
                errors.append(
                    f"{label} entry '{token}' is invalid; expected IPv4 CIDR or wildcard like 10.10.0.2*"
                )
                continue

            base = match.group(1)
            decimal_prefix = match.group(2)
            try:
                octets = [int(part) for part in base[:-1].split(".")]
            except ValueError:
                errors.append(f"{label} entry '{token}' has an invalid IPv4 prefix")
                continue

            if len(octets) != 3 or any(part < 0 or part > 255 for part in octets):
                errors.append(f"{label} entry '{token}' has an invalid IPv4 prefix")
                continue

            matched_hosts = [
                ipaddress.ip_network(f"{base}{last_octet}/32")
                for last_octet in range(256)
                if str(last_octet).startswith(decimal_prefix)
            ]
            if not matched_hosts:
                errors.append(f"{label} entry '{token}' does not match any IPv4 addresses")
                continue

            for network in ipaddress.collapse_addresses(matched_hosts):
                add(network.with_prefixlen)
            continue

        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError:
            errors.append(f"{label} entry '{token}' is not a valid CIDR")
            continue

        if network.version != 4:
            errors.append(f"{label} entry '{token}' must be IPv4")
            continue
        add(network.with_prefixlen)

    return out, errors


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
    config_project = str(config.get("project", "")).strip()
    cloud_region = os.getenv("CLOUD_REGION", "").strip()
    environment = str(config.get("environment", "")).strip()
    env_override = os.getenv("ENVIRONMENT", "").strip() or os.getenv("ENV", "").strip()
    runtime_environment = env_override or environment
    if env_override:
        # Environment is controlled by a GitHub secret in workflows; treat config/infra.yaml as a fallback.
        config["environment"] = runtime_environment

    # Base slug used for naming/state partitioning.
    # Prefer explicit PROJECT_SLUG, but fall back to infra.yaml "project" so ENVIRONMENT alone is sufficient
    # to prevent "dev" leaking into prod resource names.
    base_slug = project_slug or config_project
    if not base_slug:
        existing_prefix = str(config.get("name_prefix", "")).strip()
        if existing_prefix:
            base_slug = existing_prefix
            if environment and base_slug.endswith(f"-{environment}"):
                base_slug = base_slug[: -(len(environment) + 1)]

    if base_slug:
        if runtime_environment:
            config["name_prefix"] = f"{base_slug}-{runtime_environment}"
        else:
            config["name_prefix"] = base_slug
        if runtime_environment:
            # Keep resource names stable across envs and avoid hardcoded `dev` in infra.yaml.
            config.setdefault("db_volume", {})["name"] = f"{config['name_prefix']}-db"
            config.setdefault("s3_backend", {})["state_prefix"] = f"{base_slug}/{runtime_environment}"
    if cloud_region:
        config["location"] = cloud_region

    # Optional override to source load balancer service mappings from a GitHub secret.
    # Expected JSON format:
    #   [{"protocol":"tcp","source":80,"destination":30080}, ...]
    lb_config_raw = (os.getenv("LOAD_BALANCER_CONFIG") or os.getenv("load_balancer_config") or "").strip()
    if lb_config_raw:
        try:
            lb_config = json.loads(lb_config_raw)
        except json.JSONDecodeError as exc:
            print(f"LOAD_BALANCER_CONFIG is not valid JSON: {exc}", file=sys.stderr)
            return 1

        if not isinstance(lb_config, list) or not lb_config:
            print("LOAD_BALANCER_CONFIG must be a non-empty JSON array", file=sys.stderr)
            return 1

        def parse_port(idx: int, key: str, value) -> int | None:
            try:
                port = int(value)
            except (TypeError, ValueError):
                print(f"LOAD_BALANCER_CONFIG[{idx}].{key} must be an integer", file=sys.stderr)
                return None
            if port < 1 or port > 65535:
                print(f"LOAD_BALANCER_CONFIG[{idx}].{key} must be between 1 and 65535", file=sys.stderr)
                return None
            return port

        overridden_services = []
        seen_names = set()
        for idx, item in enumerate(lb_config):
            if not isinstance(item, dict):
                print(f"LOAD_BALANCER_CONFIG[{idx}] must be an object", file=sys.stderr)
                return 1

            protocol = str(item.get("protocol", "")).strip().lower()
            if protocol not in ("tcp", "http", "https"):
                print(
                    f"LOAD_BALANCER_CONFIG[{idx}].protocol must be one of: tcp, http, https",
                    file=sys.stderr,
                )
                return 1

            source = parse_port(idx, "source", item.get("source"))
            destination = parse_port(idx, "destination", item.get("destination"))
            if source is None or destination is None:
                return 1

            if source == 80:
                name = "http"
            elif source == 443:
                name = "https"
            else:
                name = f"{protocol}-{source}"

            if name in seen_names:
                print(f"LOAD_BALANCER_CONFIG service names must be unique (duplicate: {name})", file=sys.stderr)
                return 1
            seen_names.add(name)

            overridden_services.append(
                {
                    "name": name,
                    "protocol": protocol,
                    "listen_port": source,
                    "destination_port": destination,
                }
            )

        config.setdefault("load_balancer", {})["services"] = overridden_services

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

    def optional_multiline_env(name: str) -> str:
        value = os.getenv(name)
        if value is None:
            return ""
        return value

    debug_root_password = optional_env("DEBUG_ROOT_PASSWORD")
    config["debug_root_password"] = debug_root_password

    # Optional user-provided cloud-init overlays (stored as GitHub secrets).
    # These are merged into the generated cloud-init for each role in OpenTofu.
    config["bastion_cloud_init"] = optional_multiline_env("BASTION_CLOUD_INIT") or optional_multiline_env(
        "bastion_cloud_init"
    )
    config["egress_cloud_init"] = optional_multiline_env("EGRESS_CLOUD_INIT") or optional_multiline_env(
        "egress_cloud_init"
    )
    config["db_cloud_init"] = optional_multiline_env("DB_CLOUD_INIT") or optional_multiline_env("db_cloud_init")
    config["node_primary_cloud_init"] = optional_multiline_env("NODE_PRIMARY_CLOUD_INIT") or optional_multiline_env(
        "node_primary_cloud_init"
    )
    config["nodes_secondary_cloud_init"] = optional_multiline_env(
        "NODES_SECONDARY_CLOUD_INIT"
    ) or optional_multiline_env("nodes_secondary_cloud_init")
    config["pgbouncer_cloud_init"] = optional_multiline_env("PGBOUNCER_CLOUD_INIT") or optional_multiline_env(
        "pgbouncer_cloud_init"
    )

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

    def parse_bool(value, default: bool = False) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"true", "1", "yes", "y", "on"}:
                return True
            if lowered in {"false", "0", "no", "n", "off"}:
                return False
        return bool(value)

    def parse_platform_admins(raw: str) -> tuple[list[dict], str]:
        if not raw:
            return [], ""
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            errors.append(f"PLATFORM_ADMINS_JSON is not valid JSON: {exc}")
            return [], ""

        if not isinstance(parsed, list):
            errors.append("PLATFORM_ADMINS_JSON must be a JSON array")
            return [], ""

        admins: list[dict] = []
        seen_emails: set[str] = set()
        for idx, item in enumerate(parsed):
            if not isinstance(item, dict):
                errors.append(f"PLATFORM_ADMINS_JSON[{idx}] must be an object")
                continue

            email = str(item.get("email", "")).strip()
            argocd_password = str(item.get("argocd_password", "")).strip()
            infisical_password = str(item.get("infisical_password", "")).strip()
            grafana_password = str(item.get("grafana_password", "")).strip()
            argocd_read_only = parse_bool(item.get("argocd_read_only"), default=False)

            if not email:
                errors.append(f"PLATFORM_ADMINS_JSON[{idx}].email is required")
                continue
            if not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
                errors.append(f"PLATFORM_ADMINS_JSON[{idx}].email must be a valid email")
                continue
            email_key = email.lower()
            if email_key in seen_emails:
                errors.append(f"PLATFORM_ADMINS_JSON contains duplicate email: {email}")
                continue
            seen_emails.add(email_key)

            if not argocd_password:
                errors.append(f"PLATFORM_ADMINS_JSON[{idx}].argocd_password is required")
                continue
            if not infisical_password:
                errors.append(f"PLATFORM_ADMINS_JSON[{idx}].infisical_password is required")
                continue
            if not grafana_password:
                errors.append(f"PLATFORM_ADMINS_JSON[{idx}].grafana_password is required")
                continue

            admins.append(
                {
                    "email": email,
                    "argocd_password": argocd_password,
                    "argocd_read_only": bool(argocd_read_only),
                    "infisical_password": infisical_password,
                    "grafana_password": grafana_password,
                }
            )

        if not admins:
            return [], ""

        return admins, json.dumps(admins, separators=(",", ":"))

    servers_cfg = config.get("servers", {})
    k3s_control_planes = config.get("k3s_control_planes")
    k3s_workers = config.get("k3s_workers")

    if not isinstance(k3s_control_planes, list):
        errors.append("k3s_control_planes must be a list")
        k3s_control_planes = []
    if not isinstance(k3s_workers, list):
        errors.append("k3s_workers must be a list")
        k3s_workers = []

    k3s_control_planes_count = parse_int_env("K3S_CONTROL_PLANES_COUNT", minimum=1)
    if k3s_control_planes_count is None:
        # Source of truth is GitHub Actions secrets; fail fast if not provided.
        missing_env.append("K3S_CONTROL_PLANES_COUNT")
        k3s_control_planes_count = 1
    if k3s_control_planes_count not in (1, 3, 5):
        errors.append("K3S_CONTROL_PLANES_COUNT must be one of: 1, 3, 5")
    if len(k3s_control_planes) < k3s_control_planes_count:
        errors.append("k3s_control_planes must include at least K3S_CONTROL_PLANES_COUNT entries")

    k3s_workers_count = parse_int_env("K3S_WORKERS_COUNT", minimum=0)
    if k3s_workers_count is None:
        # Source of truth is GitHub Actions secrets; fail fast if not provided.
        missing_env.append("K3S_WORKERS_COUNT")
        k3s_workers_count = 0
    if len(k3s_workers) < k3s_workers_count:
        errors.append("k3s_workers must include at least K3S_WORKERS_COUNT entries")

    config["k3s_control_planes"] = k3s_control_planes[:k3s_control_planes_count]
    config["k3s_workers"] = k3s_workers[:k3s_workers_count]
    config["k3s_nodes"] = config["k3s_control_planes"] + config["k3s_workers"]
    config["k3s_control_planes_count"] = k3s_control_planes_count

    k3s_node_cidrs = []
    for node in config["k3s_nodes"]:
        ip = str(node.get("private_ip", "")).strip()
        if ip:
            k3s_node_cidrs.append(f"{ip}/32")

    k3s_node_cidrs_extra_raw = optional_env("K3S_NODE_CIDRS_EXTRA")
    if k3s_node_cidrs_extra_raw:
        parsed_extra_cidrs, parse_errors = parse_ipv4_cidrs_and_wildcards(
            k3s_node_cidrs_extra_raw, "K3S_NODE_CIDRS_EXTRA"
        )
        errors.extend(parse_errors)
        for cidr in parsed_extra_cidrs:
            if cidr not in k3s_node_cidrs:
                k3s_node_cidrs.append(cidr)

    k3s_node_cidr_wildcards_raw = optional_env("K3S_NODE_CIDR_WILDCARDS")
    if k3s_node_cidr_wildcards_raw:
        parsed_wildcard_cidrs, parse_errors = parse_ipv4_cidrs_and_wildcards(
            k3s_node_cidr_wildcards_raw, "K3S_NODE_CIDR_WILDCARDS"
        )
        errors.extend(parse_errors)
        for cidr in parsed_wildcard_cidrs:
            if cidr not in k3s_node_cidrs:
                k3s_node_cidrs.append(cidr)

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
    if config["k3s_control_planes"]:
        k3s_server_private_ip = str(config["k3s_control_planes"][0].get("private_ip", "")).strip()
    if not k3s_server_private_ip:
        errors.append("k3s_control_planes[0].private_ip is required for k3s server")

    k3s_api_lb_private_ip = ""
    api_lb_cfg = config.get("k3s_api_load_balancer", {}) or {}
    if isinstance(api_lb_cfg, dict):
        k3s_api_lb_private_ip = str(api_lb_cfg.get("private_ip", "")).strip()

    if k3s_control_planes_count > 1 and not k3s_api_lb_private_ip:
        errors.append("k3s_api_load_balancer.private_ip is required when K3S_CONTROL_PLANES_COUNT > 1")

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
    pgbouncer_server_type = optional_env("PGBOUNCER_SERVER_TYPE") or "cx22"

    db_type = require_env("DB_TYPE")
    db_version = require_env("DB_VERSION")
    databases_raw = require_env("DATABASES_JSON")
    databases_full: list[dict] = []
    databases_public: list[dict] = []
    databases_json_private_b64 = ""

    if databases_raw:
        try:
            parsed_databases = json.loads(databases_raw)
        except json.JSONDecodeError as exc:
            errors.append(f"DATABASES_JSON is not valid JSON: {exc}")
        else:
            if not isinstance(parsed_databases, list) or not parsed_databases:
                errors.append("DATABASES_JSON must be a non-empty JSON array")
            else:
                for idx, item in enumerate(parsed_databases):
                    if not isinstance(item, dict):
                        errors.append(f"DATABASES_JSON[{idx}] must be an object")
                        continue
                    name = str(item.get("name", "")).strip()
                    user = str(item.get("user", "")).strip()
                    password = str(item.get("password", "")).strip()
                    pub = str(item.get("backup_age_public_key", "")).strip()
                    priv = str(item.get("backup_age_private_key", "")).strip()
                    restore_latest_raw = item.get("restore_latest", True)
                    restore_dump_path_raw = item.get("restore_dump_path", "")

                    restore_latest = True
                    if "restore_latest" in item:
                        if restore_latest_raw is None:
                            restore_latest = True
                        elif isinstance(restore_latest_raw, bool):
                            restore_latest = restore_latest_raw
                        else:
                            errors.append(f"DATABASES_JSON[{idx}].restore_latest must be a boolean")
                            continue

                    restore_dump_path = ""
                    if "restore_dump_path" in item:
                        if restore_dump_path_raw is None:
                            restore_dump_path = ""
                        elif isinstance(restore_dump_path_raw, str):
                            restore_dump_path = restore_dump_path_raw.strip()
                        else:
                            errors.append(f"DATABASES_JSON[{idx}].restore_dump_path must be a string")
                            continue

                    if restore_dump_path and any(ch.isspace() for ch in restore_dump_path):
                        errors.append(
                            f"DATABASES_JSON[{idx}].restore_dump_path must not contain whitespace"
                        )
                        continue
                    if restore_dump_path and restore_dump_path.startswith("/"):
                        errors.append(
                            f"DATABASES_JSON[{idx}].restore_dump_path must not start with '/'"
                        )
                        continue
                    if restore_dump_path and restore_dump_path.startswith(("http://", "https://")):
                        errors.append(
                            f"DATABASES_JSON[{idx}].restore_dump_path must be an S3 key or s3:// URL (http(s) not supported)"
                        )
                        continue

                    if not name:
                        errors.append(f"DATABASES_JSON[{idx}].name is required")
                        continue
                    if not user:
                        errors.append(f"DATABASES_JSON[{idx}].user is required")
                        continue
                    if not password:
                        errors.append(f"DATABASES_JSON[{idx}].password is required")
                        continue
                    if not pub:
                        errors.append(f"DATABASES_JSON[{idx}].backup_age_public_key is required")
                        continue
                    if not priv:
                        errors.append(f"DATABASES_JSON[{idx}].backup_age_private_key is required")
                        continue

                    databases_full.append(
                        {
                            "name": name,
                            "user": user,
                            "password": password,
                            "backup_age_public_key": pub,
                            "backup_age_private_key": priv,
                            "restore_latest": restore_latest,
                            "restore_dump_path": restore_dump_path,
                        }
                    )

                names = [d["name"] for d in databases_full]
                if len(names) != len(set(names)):
                    errors.append("DATABASES_JSON database names must be unique")

                if databases_full:
                    databases_public = [
                        {
                            "name": d["name"],
                            "user": d["user"],
                            "password": d["password"],
                            "backup_age_public_key": d["backup_age_public_key"],
                            "restore_latest": d.get("restore_latest", True),
                            "restore_dump_path": d.get("restore_dump_path", ""),
                        }
                        for d in databases_full
                    ]
                    databases_json_private_b64 = base64.b64encode(
                        json.dumps(databases_full, separators=(",", ":")).encode("utf-8")
                    ).decode("utf-8")

    if db_type and db_type.lower() not in ("postgresql", "postgres"):
        errors.append("DB_TYPE must be 'postgresql'")
    if db_version and db_version != "14.20":
        errors.append("DB_VERSION must be '14.20'")

    infisical_restore_from_s3 = os.getenv("INFISICAL_RESTORE_FROM_S3", "").strip()
    if not infisical_restore_from_s3:
        infisical_restore_from_s3 = "false"
    restore_requested = infisical_restore_from_s3.lower() == "true"

    platform_admins_raw = optional_env("PLATFORM_ADMINS_JSON")
    if not platform_admins_raw:
        platform_admins_raw = optional_env("platform_admins_json")
    platform_admins, platform_admins_json = parse_platform_admins(platform_admins_raw)
    primary_platform_admin = platform_admins[0] if platform_admins else None

    infisical_project_name = require_env("INFISICAL_PROJECT_NAME")
    infisical_seed_email = require_env("INFISICAL_EMAIL")
    infisical_seed_password = require_env("INFISICAL_PASSWORD")
    if primary_platform_admin:
        infisical_seed_email = primary_platform_admin.get("email", infisical_seed_email)
        infisical_seed_password = primary_platform_admin.get(
            "infisical_password", infisical_seed_password
        )

    grafana_admin_password = optional_env("GRAFANA_ADMIN_PASSWORD")
    if not grafana_admin_password and primary_platform_admin:
        grafana_admin_password = primary_platform_admin.get("grafana_password", "")
    if not grafana_admin_password:
        # Deterministic secure fallback to avoid default admin/admin.
        grafana_admin_password = require_env("INFISICAL_AUTH_SECRET")

    split_bootstrap_secrets = {}
    merged_split_bootstrap_payload = {}
    split_prefix = "INFISICAL_BOOTSTRAP_SECRETS__"
    for env_name, env_value in os.environ.items():
        normalized_name = env_name.upper()
        if not normalized_name.startswith(split_prefix):
            continue
        value = str(env_value).strip()
        if not value:
            continue
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            errors.append(f"{normalized_name} is not valid JSON: {exc}")
            continue
        if not isinstance(parsed, dict):
            errors.append(f"{normalized_name} must be a JSON object")
            continue
        invalid_folder_payload = False
        for folder, folder_payload in parsed.items():
            if not isinstance(folder_payload, list):
                errors.append(
                    f"{normalized_name}.{folder} must be a JSON array"
                )
                invalid_folder_payload = True
                break
        if invalid_folder_payload:
            continue
        split_bootstrap_secrets[normalized_name] = json.dumps(parsed, separators=(",", ":"))

    infisical_bootstrap_secrets_raw = os.getenv("INFISICAL_BOOTSTRAP_SECRETS", "").strip()
    if not infisical_bootstrap_secrets_raw:
        infisical_bootstrap_secrets_raw = os.getenv("infisical_bootstrap_secrets", "").strip()
    infisical_bootstrap_secrets_gz_b64_raw = os.getenv("INFISICAL_BOOTSTRAP_SECRETS_GZ_B64", "").strip()
    if not infisical_bootstrap_secrets_gz_b64_raw:
        infisical_bootstrap_secrets_gz_b64_raw = os.getenv(
            "infisical_bootstrap_secrets_gz_b64", ""
        ).strip()
    infisical_bootstrap_secrets = ""
    infisical_bootstrap_secrets_gz_b64 = ""
    if split_bootstrap_secrets:
        for env_name in sorted(split_bootstrap_secrets):
            parsed_split_payload = json.loads(split_bootstrap_secrets[env_name])
            for folder, folder_payload in parsed_split_payload.items():
                merged_split_bootstrap_payload.setdefault(folder, [])
                merged_split_bootstrap_payload[folder].extend(folder_payload)

        merged_bootstrap_json = json.dumps(merged_split_bootstrap_payload, separators=(",", ":"))
        if len(merged_bootstrap_json) > 4096:
            infisical_bootstrap_secrets_gz_b64 = base64.b64encode(
                gzip.compress(merged_bootstrap_json.encode("utf-8"), compresslevel=9)
            ).decode("utf-8")
        else:
            infisical_bootstrap_secrets = merged_bootstrap_json
    else:
        if infisical_bootstrap_secrets_raw:
            try:
                parsed_bootstrap_secrets = json.loads(infisical_bootstrap_secrets_raw)
            except json.JSONDecodeError as exc:
                errors.append(f"INFISICAL_BOOTSTRAP_SECRETS is not valid JSON: {exc}")
            else:
                if not isinstance(parsed_bootstrap_secrets, dict):
                    errors.append("INFISICAL_BOOTSTRAP_SECRETS must be a JSON object")
                else:
                    infisical_bootstrap_secrets = json.dumps(
                        parsed_bootstrap_secrets, separators=(",", ":")
                    )
                    if len(infisical_bootstrap_secrets) > 4096:
                        infisical_bootstrap_secrets_gz_b64 = base64.b64encode(
                            gzip.compress(infisical_bootstrap_secrets.encode("utf-8"), compresslevel=9)
                        ).decode("utf-8")
                        infisical_bootstrap_secrets = ""
        elif infisical_bootstrap_secrets_gz_b64_raw:
            infisical_bootstrap_secrets_gz_b64 = infisical_bootstrap_secrets_gz_b64_raw

    infisical_db_backup_age_public_key = require_env("INFISICAL_DB_BACKUP_AGE_PUBLIC_KEY")
    infisical_db_backup_age_private_key = require_env("INFISICAL_DB_BACKUP_AGE_PRIVATE_KEY")

    egress_secrets = {
        "S3_ACCESS_KEY_ID": s3_access_key,
        "S3_SECRET_ACCESS_KEY": s3_secret_key,
        "S3_ENDPOINT": s3_endpoint,
        "S3_REGION": s3_region,
        "DB_BACKUP_BUCKET": require_env("DB_BACKUP_BUCKET"),
        "INFISICAL_DB_BACKUP_AGE_PUBLIC_KEY": infisical_db_backup_age_public_key,
        "INFISICAL_RESTORE_FROM_S3": infisical_restore_from_s3.lower(),
        "INFISICAL_PASSWORD": infisical_seed_password,
        "INFISICAL_EMAIL": infisical_seed_email,
        "INFISICAL_ORGANIZATION": require_env("INFISICAL_ORGANIZATION"),
        "INFISICAL_PROJECT_NAME": infisical_project_name,
        "INFISICAL_POSTGRES_DB": require_env("INFISICAL_POSTGRES_DB"),
        "INFISICAL_POSTGRES_USER": require_env("INFISICAL_POSTGRES_USER"),
        "INFISICAL_POSTGRES_PASSWORD": require_env("INFISICAL_POSTGRES_PASSWORD"),
        "INFISICAL_ENCRYPTION_KEY": require_env("INFISICAL_ENCRYPTION_KEY"),
        "INFISICAL_AUTH_SECRET": require_env("INFISICAL_AUTH_SECRET"),
        "GRAFANA_ADMIN_PASSWORD": grafana_admin_password,
    }

    if platform_admins_json:
        egress_secrets["PLATFORM_ADMINS_JSON"] = platform_admins_json

    db_secrets = {
        "DB_TYPE": db_type,
        "DB_VERSION": db_version,
        "DATABASES_JSON": json.dumps(databases_public, separators=(",", ":")),
        "S3_ACCESS_KEY_ID": s3_access_key,
        "S3_SECRET_ACCESS_KEY": s3_secret_key,
        "S3_ENDPOINT": s3_endpoint,
        "S3_REGION": s3_region,
        "DB_BACKUP_BUCKET": require_env("DB_BACKUP_BUCKET"),
        "K3S_NODE_CIDRS": ",".join(k3s_node_cidrs),
    }

    infisical_site_url = os.getenv("INFISICAL_SITE_URL", "").strip()
    if infisical_site_url:
        egress_secrets["INFISICAL_SITE_URL"] = infisical_site_url

    if infisical_bootstrap_secrets:
        egress_secrets["INFISICAL_BOOTSTRAP_SECRETS"] = infisical_bootstrap_secrets
    elif infisical_bootstrap_secrets_gz_b64:
        egress_secrets["INFISICAL_BOOTSTRAP_SECRETS_GZ_B64"] = infisical_bootstrap_secrets_gz_b64

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
    deployed_app_fqdns = []
    deployed_apps_json = parse_json_env("DEPLOYED_APPS_JSON")
    if deployed_apps_json is not None:
        if not isinstance(deployed_apps_json, list):
            errors.append("DEPLOYED_APPS_JSON must be a JSON array")
        else:
            for idx, app in enumerate(deployed_apps_json):
                if not isinstance(app, dict):
                    errors.append(f"DEPLOYED_APPS_JSON[{idx}] must be an object")
                    continue
                deployed_apps.append(app)

                workloads = app.get("workloads")
                if workloads is None:
                    # Legacy payload shape: app-level fqdn.
                    fqdn = str(app.get("fqdn", "")).strip()
                    if not fqdn:
                        errors.append(
                            f"DEPLOYED_APPS_JSON[{idx}].fqdn is required for legacy entries without workloads"
                        )
                        continue
                    deployed_app_fqdns.append(fqdn)
                    continue

                if not isinstance(workloads, list):
                    errors.append(f"DEPLOYED_APPS_JSON[{idx}].workloads must be a JSON array")
                    continue

                for workload_idx, workload in enumerate(workloads):
                    if not isinstance(workload, dict):
                        errors.append(f"DEPLOYED_APPS_JSON[{idx}].workloads[{workload_idx}] must be an object")
                        continue

                    kind = str(workload.get("kind", workload.get("type", ""))).strip().lower()
                    if kind in {"cronjob", "job"}:
                        continue

                    fqdn = str(workload.get("fqdn", "")).strip()
                    expose = parse_bool(workload.get("expose"), default=bool(fqdn))
                    if expose and not fqdn:
                        errors.append(
                            f"DEPLOYED_APPS_JSON[{idx}].workloads[{workload_idx}].fqdn is required when expose=true"
                        )
                        continue
                    if expose and fqdn:
                        deployed_app_fqdns.append(fqdn)

    cloudflare_api_token = optional_env("CLOUDFLARE_API_TOKEN")
    if (internal_services or deployed_app_fqdns) and not cloudflare_api_token:
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
    if k3s_control_planes_count > 1 and k3s_api_lb_private_ip:
        egress_secrets["K3S_API_LB_PRIVATE_IP"] = k3s_api_lb_private_ip
    if not infisical_site_url and infisical_fqdn:
        infisical_site_url = f"https://{infisical_fqdn}"
        egress_secrets["INFISICAL_SITE_URL"] = infisical_site_url

    if db_fqdn:
        db_secrets["DB_FQDN"] = db_fqdn
    if cloudflare_api_token:
        db_secrets["CLOUDFLARE_API_TOKEN"] = cloudflare_api_token
    if egress_secrets.get("INFISICAL_EMAIL"):
        db_secrets["INFISICAL_EMAIL"] = egress_secrets.get("INFISICAL_EMAIL", "")

    # DB Replication
    db_replica_enabled = parse_bool(optional_env("DB_REPLICA_ENABLED"), default=False)
    db_replica_count = 0
    if db_replica_enabled:
        db_replica_count_raw = optional_env("DB_REPLICA_COUNT")
        if db_replica_count_raw:
            try:
                db_replica_count = int(db_replica_count_raw)
            except ValueError:
                errors.append("DB_REPLICA_COUNT must be an integer")
            if db_replica_count < 1 or db_replica_count > 3:
                errors.append("DB_REPLICA_COUNT must be between 1 and 3")
                db_replica_count = 0

    db_replicas_cfg = config.get("db_replicas", [])
    if not isinstance(db_replicas_cfg, list):
        db_replicas_cfg = []

    # Auto-generate replica IPs if not defined in config
    db_primary_ip = str(servers_cfg.get("db", {}).get("private_ip", "")).strip()
    if db_replica_enabled and db_replica_count > 0 and len(db_replicas_cfg) < db_replica_count:
        if db_primary_ip:
            try:
                primary_addr = ipaddress.ip_address(db_primary_ip)
                for i in range(len(db_replicas_cfg), db_replica_count):
                    replica_ip = str(primary_addr + 1 + i)
                    db_replicas_cfg.append({
                        "private_ip": replica_ip,
                        "public_ipv4": False,
                        "public_ipv6": False,
                    })
            except (ValueError, TypeError):
                errors.append("Cannot auto-generate replica IPs from db.private_ip")

    config["db_replicas"] = db_replicas_cfg[:db_replica_count] if db_replica_enabled else []

    db_replica_cidrs = [f"{r['private_ip']}/32" for r in config["db_replicas"] if r.get("private_ip")]
    if db_replica_enabled:
        db_secrets["DB_REPLICA_ENABLED"] = "true"
        db_secrets["DB_REPLICA_COUNT"] = str(db_replica_count)
        if db_replica_cidrs:
            db_secrets["DB_REPLICA_CIDRS"] = ",".join(db_replica_cidrs)

        # Generate a replication password deterministically from existing secrets
        # so it's stable across runs without needing a new GitHub secret.
        repl_seed = (s3_secret_key or "") + (db_primary_ip or "") + "replicator"
        repl_password = hashlib.sha256(repl_seed.encode("utf-8")).hexdigest()[:32]
        db_secrets["DB_REPLICATION_USER"] = "replicator"
        db_secrets["DB_REPLICATION_PASSWORD"] = repl_password

    config["db_replica_secrets"] = {}
    if db_replica_enabled and db_replica_count > 0:
        config["db_replica_secrets"] = {
            "DB_REPLICATION_USER": "replicator",
            "DB_REPLICATION_PASSWORD": db_secrets.get("DB_REPLICATION_PASSWORD", ""),
            "DB_TYPE": db_type,
            "DB_VERSION": db_version,
            "K3S_NODE_CIDRS": ",".join(k3s_node_cidrs),
        }

    # ------------------------------------------------------------------ #
    #  PgBouncer + Patroni HA                                              #
    # ------------------------------------------------------------------ #

    pgbouncer_enabled = parse_bool(optional_env("PGBOUNCER_ENABLED"), default=False)
    patroni_enabled = parse_bool(optional_env("PATRONI_ENABLED"), default=False)

    # Patroni requires at least one replica and HA k3s (embedded etcd)
    if patroni_enabled and not db_replica_enabled:
        errors.append("PATRONI_ENABLED=true requires DB_REPLICA_ENABLED=true")
    if patroni_enabled and k3s_control_planes_count < 3:
        errors.append("PATRONI_ENABLED=true requires K3S_CONTROL_PLANES_COUNT >= 3 (embedded etcd)")

    # Build etcd endpoints from K3s control plane IPs
    etcd_endpoints = ""
    if patroni_enabled and config.get("k3s_control_planes"):
        etcd_ips = [
            str(node.get("private_ip", "")).strip()
            for node in config["k3s_control_planes"]
            if node.get("private_ip")
        ]
        etcd_endpoints = ",".join(f"{ip}:2379" for ip in etcd_ips)

    # Patroni scope: <name_prefix>-db
    patroni_scope = f"{config.get('name_prefix', 'infrazero')}-db"

    # Deterministic superuser password for Patroni
    patroni_superuser_password = ""
    if patroni_enabled:
        seed = (s3_secret_key or "") + (db_primary_ip or "") + "patroni-superuser"
        patroni_superuser_password = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]

    if patroni_enabled:
        db_secrets["PATRONI_ENABLED"] = "true"
        db_secrets["PATRONI_SCOPE"] = patroni_scope
        db_secrets["PATRONI_ETCD_HOSTS"] = etcd_endpoints
        db_secrets["PATRONI_SUPERUSER_PASSWORD"] = patroni_superuser_password
        db_secrets["PATRONI_NAME"] = "db-primary"
        if db_replica_enabled:
            db_secrets["DB_REPLICA_HOSTS"] = ",".join(
                r["private_ip"] for r in config["db_replicas"] if r.get("private_ip")
            )

    if patroni_enabled and db_replica_enabled and db_replica_count > 0:
        config["db_replica_secrets"]["PATRONI_ENABLED"] = "true"
        config["db_replica_secrets"]["PATRONI_SCOPE"] = patroni_scope
        config["db_replica_secrets"]["PATRONI_ETCD_HOSTS"] = etcd_endpoints
        config["db_replica_secrets"]["PATRONI_SUPERUSER_PASSWORD"] = patroni_superuser_password
        # Each replica gets a unique name via index; bootstrap script uses hostname by default
        # PATRONI_NAME is left unset so Patroni uses hostname (unique per VM)

    # PgBouncer server config
    pgbouncer_private_ip = ""
    if pgbouncer_enabled:
        pgbouncer_cfg = servers_cfg.get("pgbouncer", {}) or {}
        pgbouncer_private_ip = str(pgbouncer_cfg.get("private_ip", "")).strip()
        if not pgbouncer_private_ip:
            # Auto-generate: db_primary_ip + offset
            if db_primary_ip:
                try:
                    pgbouncer_private_ip = str(ipaddress.ip_address(db_primary_ip) + 5)
                except (ValueError, TypeError):
                    errors.append("Cannot auto-generate pgbouncer IP from db.private_ip")
            else:
                errors.append("servers.pgbouncer.private_ip or servers.db.private_ip is required when PGBOUNCER_ENABLED=true")

        if pgbouncer_private_ip:
            config.setdefault("servers", {})["pgbouncer"] = {
                "private_ip": pgbouncer_private_ip,
                "public_ipv4": bool(pgbouncer_cfg.get("public_ipv4", False)),
                "public_ipv6": bool(pgbouncer_cfg.get("public_ipv6", False)),
            }

    # PgBouncer auth credentials
    pgbouncer_auth_user = optional_env("PGBOUNCER_AUTH_USER") or "pgbouncer"
    pgbouncer_auth_password = optional_env("PGBOUNCER_AUTH_PASSWORD")
    if pgbouncer_enabled and not pgbouncer_auth_password:
        # Derive deterministically
        seed = (s3_secret_key or "") + (pgbouncer_private_ip or "") + "pgbouncer-auth"
        pgbouncer_auth_password = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]

    config["pgbouncer_secrets"] = {}
    if pgbouncer_enabled:
        config["pgbouncer_secrets"] = {
            "DB_PRIMARY_HOST": db_primary_ip,
            "PGBOUNCER_AUTH_USER": pgbouncer_auth_user,
            "PGBOUNCER_AUTH_PASSWORD": pgbouncer_auth_password,
        }
        if db_replica_enabled and config["db_replicas"]:
            replica_ips = [r["private_ip"] for r in config["db_replicas"] if r.get("private_ip")]
            config["pgbouncer_secrets"]["DB_REPLICA_HOSTS"] = ",".join(replica_ips)
        if patroni_enabled:
            config["pgbouncer_secrets"]["PATRONI_SCOPE"] = patroni_scope
            config["pgbouncer_secrets"]["PATRONI_ETCD_HOSTS"] = etcd_endpoints

    if project_slug:
        egress_secrets["PROJECT_SLUG"] = project_slug
    if runtime_environment:
        egress_secrets["ENVIRONMENT"] = runtime_environment

    # Expose replica hosts so Infisical bootstrap can write DATABASE_READ_HOST
    if db_replica_enabled and config["db_replicas"]:
        replica_ips = [r["private_ip"] for r in config["db_replicas"] if r.get("private_ip")]
        if replica_ips:
            egress_secrets["DB_REPLICA_HOSTS"] = ",".join(replica_ips)

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
    ghcr_token = optional_env("GHCR_TOKEN")
    infisical_spc_namespace = optional_env("INFISICAL_SPC_NAMESPACE")
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

    # Don't leak config-only objects into tofu.tfvars.json (OpenTofu warns on
    # undeclared variables). We read `argocd` here for derived settings only.
    argocd_cfg = config.get("argocd", {}) or {}
    config.pop("argocd", None)
    argocd_repo_path = str(argocd_cfg.get("repo_path", "")).strip()
    argocd_repo_revision = str(argocd_cfg.get("repo_revision", "")).strip() or "main"
    argocd_app_name = str(argocd_cfg.get("app_name", "")).strip() or "root"
    argocd_app_project = str(argocd_cfg.get("app_project", "")).strip() or "default"
    argocd_dest_namespace = str(argocd_cfg.get("destination_namespace", "")).strip() or "argocd"
    argocd_dest_server = str(argocd_cfg.get("destination_server", "")).strip() or "https://kubernetes.default.svc"

    def expand_env_template(value: str) -> str:
        if not value:
            return value
        env_value = runtime_environment or environment
        if not env_value:
            return value
        replacements = {
            "${ENVIRONMENT}": env_value,
            "${ENV}": env_value,
            "{ENVIRONMENT}": env_value,
            "{ENV}": env_value,
            "{environment}": env_value,
            "{env}": env_value,
        }
        for key, replacement in replacements.items():
            value = value.replace(key, replacement)
        return value

    if not argocd_repo_path:
        default_env = runtime_environment or environment
        if default_env:
            argocd_repo_path = f"clusters/{default_env}"

    argocd_repo_path = expand_env_template(argocd_repo_path)
    if runtime_environment and environment and argocd_repo_path == f"clusters/{environment}":
        argocd_repo_path = f"clusters/{runtime_environment}"

    argocd_repo_url, repo_errors = resolve_repo_url(gh_gitops_repo, gh_owner)
    if repo_errors:
        errors.extend(repo_errors)

    argocd_enabled = bool(argocd_repo_path and argocd_repo_url)
    if argocd_repo_path and not gh_gitops_repo:
        missing_env.append("GH_GITOPS_REPO")
    if gh_gitops_repo and not argocd_repo_path:
        errors.append("argocd.repo_path is required when GH_GITOPS_REPO is set")

    argocd_admin_password = optional_env("ARGOCD_ADMIN_PASSWORD")
    if not argocd_admin_password and primary_platform_admin:
        argocd_admin_password = primary_platform_admin.get("argocd_password", "")
    if argocd_enabled and not argocd_admin_password:
        missing_env.append("ARGOCD_ADMIN_PASSWORD")
    if argocd_enabled and not gh_token:
        missing_env.append("GH_TOKEN")

    egress_private_ip = str(servers_cfg.get("egress", {}).get("private_ip", "")).strip()
    k3s_server_url = ""
    if k3s_control_planes_count > 1 and k3s_api_lb_private_ip:
        k3s_server_url = f"https://{k3s_api_lb_private_ip}:6443"
    elif k3s_server_private_ip:
        k3s_server_url = f"https://{k3s_server_private_ip}:6443"
    k3s_secrets = {
        "K3S_TOKEN": k3s_token,
        "K3S_SERVER_IP": k3s_server_private_ip,
        "K3S_SERVER_URL": k3s_server_url,
        "K3S_CONTROL_PLANES_COUNT": str(k3s_control_planes_count),
        "K3S_WORKERS_COUNT": str(k3s_workers_count),
        "K3S_API_LB_PRIVATE_IP": k3s_api_lb_private_ip,
        "K3S_SERVER_TAINT": str(bool(k3s_cfg.get("server_taint", False))).lower(),
        "EGRESS_LOKI_URL": f"http://{egress_private_ip}:3100/loki/api/v1/push" if egress_private_ip else "",
    }

    k3s_server_secrets = {}
    k3s_agent_secrets = {}

    if argocd_admin_password:
        k3s_server_secrets["ARGOCD_ADMIN_PASSWORD"] = argocd_admin_password
    if platform_admins_json:
        k3s_server_secrets["PLATFORM_ADMINS_JSON"] = platform_admins_json
    if gh_token:
        k3s_server_secrets["GH_TOKEN"] = gh_token
    if gh_owner:
        k3s_server_secrets["GH_OWNER"] = gh_owner
    if ghcr_token:
        k3s_server_secrets["GHCR_TOKEN"] = ghcr_token
    if infisical_spc_namespace:
        k3s_server_secrets["INFISICAL_SPC_NAMESPACE"] = infisical_spc_namespace
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
        }
    )
    k3s_server_secrets.update(
        {
            "S3_ACCESS_KEY_ID": s3_access_key,
            "S3_SECRET_ACCESS_KEY": s3_secret_key,
            "S3_ENDPOINT": s3_endpoint,
            "S3_REGION": s3_region,
            "DB_BACKUP_BUCKET": egress_secrets.get("DB_BACKUP_BUCKET", ""),
            "INFISICAL_DB_BACKUP_AGE_PUBLIC_KEY": egress_secrets.get("INFISICAL_DB_BACKUP_AGE_PUBLIC_KEY", ""),
            "INFISICAL_DB_BACKUP_AGE_PRIVATE_KEY": infisical_db_backup_age_private_key,
            "INFISICAL_RESTORE_FROM_S3": infisical_restore_from_s3.lower(),
        }
    )
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
    config["pgbouncer_server_type"] = pgbouncer_server_type
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
    config["infisical_db_backup_age_private_key"] = infisical_db_backup_age_private_key
    config["databases_json_private_b64"] = databases_json_private_b64
    config["wg_server_address"] = wg_server_address

    if args.bootstrap_artifacts:
        artifacts = load_json(Path(args.bootstrap_artifacts))
        required_roles = list(REQUIRED_ROLES)
        if db_replica_enabled and db_replica_count > 0:
            required_roles.append("db-replica")
        if pgbouncer_enabled:
            required_roles.append("pgbouncer")
        missing = [role for role in required_roles if role not in artifacts]
        if missing:
            print(f"Missing bootstrap artifacts for roles: {', '.join(missing)}", file=sys.stderr)
            return 1
        config["bootstrap_artifacts"] = artifacts
    else:
        config["bootstrap_artifacts"] = {}

    # OpenTofu consumes k3s nodes as a single ordered list (control planes first),
    # along with k3s_control_planes_count. The explicit lists live in config/infra.yaml
    # for readability but are not needed in tofu vars.
    config.pop("k3s_control_planes", None)
    config.pop("k3s_workers", None)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(config, indent=2))
    print(f"Rendered {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
