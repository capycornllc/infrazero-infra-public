import argparse
import json
import os
import sys
from pathlib import Path

import requests
import yaml


SERVICE_KEYS = ("bastion", "grafana", "loki", "infisical", "db")


def load_yaml(path: Path):
    return yaml.safe_load(path.read_text()) or {}


def parse_json_env(name: str):
    raw = os.getenv(name, "").strip()
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{name} is not valid JSON: {exc}") from exc


def resolve_internal_fqdns():
    internal_services = {}
    internal_services_json = parse_json_env("INTERNAL_SERVICES_DOMAINS_JSON")
    if internal_services_json is not None:
        if not isinstance(internal_services_json, dict):
            raise ValueError("INTERNAL_SERVICES_DOMAINS_JSON must be a JSON object")
        for key in SERVICE_KEYS:
            value = internal_services_json.get(key)
            if not isinstance(value, dict):
                raise ValueError(f"INTERNAL_SERVICES_DOMAINS_JSON.{key} must be an object with fqdn")
            fqdn = str(value.get("fqdn", "")).strip()
            if not fqdn:
                raise ValueError(f"INTERNAL_SERVICES_DOMAINS_JSON.{key}.fqdn is required")
            internal_services[key] = fqdn
        return internal_services

    env_map = {
        "bastion": "BASTION_FQDN",
        "grafana": "GRAFANA_FQDN",
        "loki": "LOKI_FQDN",
        "infisical": "INFISICAL_FQDN",
        "db": "DB_FQDN",
    }
    for key, env_name in env_map.items():
        fqdn = os.getenv(env_name, "").strip()
        if fqdn:
            internal_services[key] = fqdn
    return internal_services


def resolve_deployed_apps():
    deployed_apps = []
    deployed_apps_json = parse_json_env("DEPLOYED_APPS_JSON")
    if deployed_apps_json is None:
        return deployed_apps
    if not isinstance(deployed_apps_json, list):
        raise ValueError("DEPLOYED_APPS_JSON must be a JSON array")
    for idx, app in enumerate(deployed_apps_json):
        if not isinstance(app, dict):
            raise ValueError(f"DEPLOYED_APPS_JSON[{idx}] must be an object")
        fqdn = str(app.get("fqdn", "")).strip()
        if not fqdn:
            raise ValueError(f"DEPLOYED_APPS_JSON[{idx}].fqdn is required")
        deployed_apps.append(app)
    return deployed_apps


def cloudflare_request(token: str, method: str, path: str, params=None, json_body=None):
    url = f"https://api.cloudflare.com/client/v4{path}"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    response = requests.request(method, url, headers=headers, params=params, json=json_body, timeout=30)
    try:
        payload = response.json()
    except ValueError:
        payload = {"success": False, "errors": [{"message": response.text}]}
    if not response.ok or not payload.get("success"):
        errors = payload.get("errors") or []
        message = "; ".join(err.get("message", "unknown error") for err in errors) or response.text
        raise RuntimeError(f"Cloudflare API error ({method} {path}): {message}")
    return payload


def list_zones(token: str):
    zones = []
    page = 1
    while True:
        payload = cloudflare_request(
            token,
            "GET",
            "/zones",
            params={"page": page, "per_page": 50, "status": "active"},
        )
        zones.extend(payload.get("result", []))
        info = payload.get("result_info") or {}
        if page >= info.get("total_pages", 1):
            break
        page += 1
    return {zone["name"]: zone["id"] for zone in zones}


def find_zone_id(fqdn: str, zones: dict[str, str]) -> str | None:
    for zone_name in sorted(zones.keys(), key=len, reverse=True):
        if fqdn == zone_name or fqdn.endswith(f".{zone_name}"):
            return zones[zone_name]
    return None


def upsert_record(token: str, zone_id: str, name: str, content: str, proxied: bool):
    payload = cloudflare_request(
        token,
        "GET",
        f"/zones/{zone_id}/dns_records",
        params={"type": "A", "name": name, "per_page": 1},
    )
    records = payload.get("result", [])
    record_data = {"type": "A", "name": name, "content": content, "proxied": proxied, "ttl": 1}

    if records:
        record_id = records[0]["id"]
        current = records[0]
        if (
            current.get("content") == content
            and bool(current.get("proxied")) == proxied
            and current.get("ttl") in (1, None)
        ):
            print(f"Cloudflare DNS: {name} already up to date")
            return
        cloudflare_request(
            token,
            "PUT",
            f"/zones/{zone_id}/dns_records/{record_id}",
            json_body=record_data,
        )
        print(f"Cloudflare DNS: updated {name} -> {content} (proxied={proxied})")
        return

    cloudflare_request(
        token,
        "POST",
        f"/zones/{zone_id}/dns_records",
        json_body=record_data,
    )
    print(f"Cloudflare DNS: created {name} -> {content} (proxied={proxied})")


def main() -> int:
    parser = argparse.ArgumentParser(description="Sync Cloudflare DNS records for internal services and apps.")
    parser.add_argument("--config", default="config/infra.yaml")
    parser.add_argument("--lb-ip", required=True)
    args = parser.parse_args()

    token = os.getenv("CLOUDFLARE_API_TOKEN", "").strip()
    if not token:
        print("CLOUDFLARE_API_TOKEN is not set; skipping DNS sync.")
        return 0

    config = load_yaml(Path(args.config))
    servers = config.get("servers", {})

    bastion_ip = str(servers.get("bastion", {}).get("private_ip", "")).strip()
    egress_ip = str(servers.get("egress", {}).get("private_ip", "")).strip()
    db_ip = str(servers.get("db", {}).get("private_ip", "")).strip()

    try:
        internal_fqdns = resolve_internal_fqdns()
        deployed_apps = resolve_deployed_apps()
    except ValueError as exc:
        print(f"Invalid DNS inputs: {exc}", file=sys.stderr)
        return 1

    records = []
    if internal_fqdns:
        if not all([bastion_ip, egress_ip, db_ip]):
            print("servers.bastion/egress/db.private_ip must be set in config/infra.yaml", file=sys.stderr)
            return 1
        service_ip_map = {
            "bastion": bastion_ip,
            "grafana": egress_ip,
            "loki": egress_ip,
            "infisical": egress_ip,
            "db": db_ip,
        }
        for key, fqdn in internal_fqdns.items():
            ip = service_ip_map.get(key)
            if ip:
                records.append({"name": fqdn, "content": ip, "proxied": False})

    if deployed_apps and not args.lb_ip.strip():
        print("lb-ip is required when deployed_apps_json is provided.", file=sys.stderr)
        return 1

    for app in deployed_apps:
        fqdn = str(app.get("fqdn", "")).strip()
        if fqdn:
            records.append({"name": fqdn, "content": args.lb_ip, "proxied": True})

    if not records:
        print("No FQDNs provided; skipping DNS sync.")
        return 0

    try:
        zones = list_zones(token)
        if not zones:
            raise RuntimeError("No active zones found in Cloudflare account.")

        for record in records:
            zone_id = find_zone_id(record["name"], zones)
            if not zone_id:
                raise RuntimeError(f"No matching Cloudflare zone for {record['name']}")
            upsert_record(token, zone_id, record["name"], record["content"], record["proxied"])
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
