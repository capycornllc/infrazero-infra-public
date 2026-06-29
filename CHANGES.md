# CHANGES

Файл изменений, вносимых в рамках поддержки проекта.

---

## 2026-06-30 — Bootstrap: исправление запуска Patroni/PostgreSQL из коробки

### Проблема
После первого деплоя кластер Patroni требовал ручного вмешательства:
- `pending_restart` на обоих узлах сразу после старта
- При failover старый primary не мог реджойниться автоматически (`pg_rewind` падал с WAL divergence)
- Ошибки в логах pgbouncer-watcher.timer из-за `beacon_status` вне bootstrap-контекста

### Изменения

#### `bootstrap/hetzner/db.sh`

**Конфликт конфигураций (`pending_restart`)**
- `setup_replication_primary()` теперь пропускается когда `PATRONI_ENABLED=true`
- Причина: функция писала `max_wal_senders = replica_count+2` (= 3) в `postgresql.conf`,
  а Patroni DCS хранит `max_wal_senders: 5`. Расхождение → `pending_restart` при каждом деплое.
- Когда Patroni включён, он сам управляет всеми WAL-параметрами через DCS.

**Fallback на basebackup при сбое pg_rewind**
- В секцию `postgresql:` patroni.yml добавлены:
  ```yaml
  create_replica_methods:
    - basebackup
  basebackup:
    max-rate: 100M
    checkpoint: fast
  ```
- Теперь при неудаче `pg_rewind` (расхождение WAL после failover) Patroni автоматически
  делает `pg_basebackup` вместо бесконечного retry. Ручной `patronictl reinit` больше не нужен.

**Ожидание etcd перед стартом Patroni**
- Создаётся `/usr/local/sbin/wait-etcd.sh` — читает etcd-хосты из `patroni.yml` и ждёт
  доступности (до 150 с) перед запуском Patroni.
- В `patroni.service` добавлен `ExecStartPre=/usr/local/sbin/wait-etcd.sh`.
- `TimeoutSec=30` заменён на `TimeoutStartSec=300` / `TimeoutStopSec=60`.
- `RestartSec=5s` → `RestartSec=10s` — меньше агрессивных рестартов при недоступном etcd.

#### `bootstrap/hetzner/db-replica.sh`

- Те же изменения patroni.yml (`create_replica_methods` + `basebackup`) и `patroni.service`
  (`wait-etcd.sh`, таймауты), что и в `db.sh`.

#### `bootstrap/hetzner/pgbouncer.sh`

**beacon_status в systemd-контексте**
- В `update-pgbouncer.sh` (watcher, запускается systemd timer) убран вызов `beacon_status` —
  функция определена только во время bootstrap и недоступна в контексте timer.
- Заменено на `log` + `exit 0`.

---

## (предыдущие изменения — другие файлы)

- `bootstrap/hetzner/egress.sh` — восстановлены ~80 обрезанных строк (infisical retry timer,
  backup.sh, cron, beacon_status "complete")
- `bootstrap/hetzner/bastion.sh` — восстановлен `systemctl enable --now promtail`
- `bootstrap/hetzner/common.sh` — восстановлен блок journald persistence
- `tofu/hetzner/main.tf` — восстановлен `lifecycle { prevent_destroy = true }` блок;
  `db_replica.depends_on` расширен для исправления race condition при деплое
- `tofu/hetzner/templates/cloud-init.tftpl` — восстановлена директива
  `%{ if length(node_role_env) > 0 ~}` (была удалена → unbalanced endif);
  добавлен `HAS_PUBLIC_IPV4=true` для bastion/egress ролей
