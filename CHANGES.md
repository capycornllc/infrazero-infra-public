# CHANGES

Файл изменений, вносимых в рамках поддержки проекта.

---

## 2026-06-30

### Fix: db.sh — replication user password desync on redeploy

**Root cause:** `setup_patroni()` in `db.sh` temporarily starts PostgreSQL only to set
the `postgres` superuser password before handing off to Patroni. The `replicator` role
password was never updated in this block. On first deploy Patroni bootstraps a new cluster
and creates the replication user with `DB_REPLICATION_PASSWORD`. On subsequent redeploys
the cluster already exists in etcd — Patroni does NOT recreate users, so the replication
user keeps the password from the first deploy. If `DB_REPLICATION_PASSWORD` differs between
deploys (or the stored value in etcd diverges), `db-replica.sh`'s `pg_basebackup` fails
with `FATAL: password authentication failed for user "replicator"`.

**Fix:** `bootstrap/hetzner/db.sh` `setup_patroni()` — expanded the temporary PostgreSQL
start block to also `CREATE OR ALTER` the replication user with the current
`DB_REPLICATION_PASSWORD`. Condition widened to `|| [ -n "$repl_password" ]` so the block
runs even when `PATRONI_SUPERUSER_PASSWORD` is empty. This ensures the replication user
password is always in sync with the deploy's secrets before Patroni takes over.


### Fix: Patroni pending_restart на max_wal_senders и max_replication_slots

**Root cause:** DCS bootstrap параметры в `patroni.yml` задавали `max_wal_senders: 5`
и `max_replication_slots: 5`, тогда как PostgreSQL 14+ по умолчанию ставит оба в 10.
После старта Patroni видел расхождение (running=10, DCS=5) и выставлял `pending_restart`
на primary с первого же деплоя — без какого-либо ручного вмешательства применить нельзя.

**Fix:** `bootstrap/hetzner/db.sh` и `bootstrap/hetzner/db-replica.sh` — изменены
DCS bootstrap параметры: `max_wal_senders: 5 → 10`, `max_replication_slots: 5 → 10`.
Теперь DCS совпадает с PostgreSQL default → `pending_restart` не появляется.

### Fix: db-replica pg_basebackup race condition with Patroni

**Root cause:** When `PATRONI_ENABLED=true`, `db.sh` intentionally skips
`setup_replication_primary` to avoid conflicting WAL settings. As a result,
vanilla `pg_hba.conf` has no replication entry for the replica IP. Meanwhile
`db-replica.sh` starts simultaneously, sees `pg_isready` succeed on port 5432
(vanilla PostgreSQL still up), and immediately runs `pg_basebackup` — which
fails with `FATAL: no pg_hba.conf entry for replication from 10.10.0.31`.
By the time Patroni starts and writes its own pg_hba (`0.0.0.0/0`), all 30
retry attempts (30 × 15s = 7.5 min) are exhausted and the replica exits.

**Fix:** `bootstrap/hetzner/db-replica.sh` — when `PATRONI_ENABLED=true`,
wait for the primary Patroni REST API (`/leader` on port 8008) before
attempting `pg_basebackup`. Once Patroni is leader, it has written the
correct pg_hba and PostgreSQL is stable. Falls through after 120 × 5s
timeout with a warning so non-Patroni setups are unaffected.


### Fix: egress enp7s0 race condition — надёжное ожидание IP от Hetzner

**Root cause (баг 1 — egress.sh):** `_find_private_if()` находит `enp7s0` по MAC-префиксу
`86:00:00:` без проверки наличия IP. Внешний цикл обнаружения интерфейсов сразу выходит,
как только нашёл интерфейс по MAC. Если Hetzner cloud-init ещё не присвоил IP — self-configure
блок срабатывает, но `EGRESS_PRIVATE_IP` отсутствует в `egress.env` → enp7s0 остаётся
без IP → egress.sh падает. Баг недетерминированный: когда Hetzner быстрый — работает.

**Fix (egress.sh):** добавлен wait loop до 60 сек (12 × 5s) после нахождения
`PRIVATE_IF_NAME` по MAC — ждём пока Hetzner cloud-init назначит IP на enp7s0.
Self-configure вызывается только если IP так и не появился после ожидания.

**Root cause (баг 2 — common.sh wg-route):** `ip route get $private_gw` на egress
когда enp7s0 без IP возвращает eth0 через default route (нет специфичного маршрута к
10.10.0.1). В итоге WG маршрут `10.50.0.0/24` устанавливался через публичный интерфейс.

**Fix (common.sh):** убран `ip route get` как первичный метод детекции интерфейса.
Используется только python IP-in-CIDR проверка — она надёжная: матчит только интерфейс
с реальным IP внутри приватной сети. Старый код сохранён в комментарии.

### Fix: egress enp7s0 stays DOWN on rebuild (variable name mismatch)

**Root cause:** `egress.sh` read `${PRIVATE_IP:-}` to self-configure the private
interface when Hetzner cloud-init hadn't done it yet. But Terraform cloud-init
injects the variable as `EGRESS_PRIVATE_IP` (in `/etc/infrazero/egress.env`),
not `PRIVATE_IP`. So the fallback block never had a value → `ip link set enp7s0 up`
was never called → `enp7s0` stayed DOWN non-deterministically (race condition: if
Hetzner was fast enough the fallback wasn't needed; if slow the fallback failed).

**Fix:** `bootstrap/hetzner/egress.sh` line 411:
```
_expected_priv_ip="${EGRESS_PRIVATE_IP:-${PRIVATE_IP:-}}"
```

**Action required:** run `rebuild-egress` to apply. — Bootstrap: исправление запуска Patroni/PostgreSQL из коробки

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
