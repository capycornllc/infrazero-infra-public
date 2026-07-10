#!/usr/bin/env bash

render_patroni_pg_hba() {
  local repl_user="${1:-}"
  local private_cidr="${2:-}"

  if [ -z "$repl_user" ]; then
    echo "[db-patroni] missing replication user" >&2
    return 1
  fi

  if [ -z "$private_cidr" ]; then
    echo "[db-patroni] missing private CIDR" >&2
    return 1
  fi

  cat <<EOF
    - local all postgres peer
    - local all all peer
    - host all postgres 127.0.0.1/32 scram-sha-256
    - host all all 127.0.0.1/32 scram-sha-256
    - host replication ${repl_user} 127.0.0.1/32 scram-sha-256
    - host replication ${repl_user} ${private_cidr} scram-sha-256
    - host all all ${private_cidr} scram-sha-256
EOF
}
