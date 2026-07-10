# Пофайловый план объединения (Hetzner/OVH → common + adapter) под AWS/Azure/GCP

Дата: 2026-07-10. Основан на измерении реального сходства файлов (comm по
отсортированным строкам после нормализации CRLF) и пофункционального diff'а между
провайдерами. Продолжает `infra-cloud-commonization-plan.md` (Codex) и
`codex-commonization-review.md`, но конкретизирует ДО УРОВНЯ ФАЙЛОВ И ФУНКЦИЙ.

## Сводка измеренных дублей

| Файл (hetzner vs ovh)         | Строк h/o  | Идентично | Вывод                          |
|-------------------------------|-----------|-----------|--------------------------------|
| bootstrap db.sh               | 2765/2806 | 2413 (87%)| объединяется почти целиком     |
| bootstrap bastion.sh          | 497/428   | 333       | объединяется, adapter route/SNAT |
| bootstrap common.sh           | 442/421   | 290       | route-генераторы почти идентичны |
| bootstrap egress.sh           | 793/752   | 75        | уже разделён; остатки — NIC + Loki/Grafana |
| tofu cloud-init.tf            | 214/213   | 189       | объединяется почти целиком     |
| tofu variables.tf             | 336/354   | 246 (46 общих переменных, 2 h-only, 11 o-only) | делится на common + provider |
| tofu locals.tf                | 91/87     | 72        | делится                        |
| tofu cloud-init.tftpl         | 365/258   | 230       | один шаблон; OVH отстаёт по error handling |
| tofu main.tf                  | 776/943   | 121       | НЕ объединять (ресурсы провайдера) |
| scripts import-ssh-keys.py    | 259/116   | 72        | общий каркас + provider API    |
| scripts destroy-without-volume.sh | 119/161 | 47      | общий каркас + список ресурсов |
| workflows (6 файлов)          | 1954 суммарно | блок "Determine cloud provider" скопирован 6 раз (4 — байт-в-байт) | composite action |

db.sh: имена всех 59 функций совпадают в обоих облаках; различаются тела только у
`find_db_volume_device`, `find_volume_device`, `wait_for_db_volume_device` (тайминги
45×2s vs 360×5s) и одна строка в `setup_replication_primary`
(`max_wal_senders`: h — `replica_count+2`, o — `${DB_MAX_WAL_SENDERS:-10}`).

## Целевая структура

```text
bootstrap/
  common/                    # уже есть; сюда добавляются common-db.sh, common-bastion.sh,
    lib/                     # (опц., этап 7) разбивка common-base.sh на модули
  providers/
    hetzner/adapter.sh
    ovh/adapter.sh
    aws/adapter.sh           # будущее: один файл на облако
  hetzner/  ovh/             # остаются только обёртки + переходный период
tofu/
  modules/cloud-init/        # общий рендер cloud-init (шаблон + locals)
  hetzner/  ovh/  aws/       # main.tf, versions.tf, variables-provider.tf, тонкий cloud-init.tf
scripts/
  common/                    # + gitops-preflight.sh (он cloud-neutral!), + import-ssh-keys.py каркас
  hetzner/  ovh/             # только provider API: volume-id, cleanup, nuke, ресурс-списки
.github/
  actions/select-provider/   # composite action вместо 6 копий блока
  workflows/                 # rebuild-* сводятся к одному reusable workflow
```

## План по файлам

### Этап 1 — контракт адаптера (фундамент, делается первым)

Создать `bootstrap/providers/{hetzner,ovh}/adapter.sh` и `docs/provider-adapter-contract.md`.
Обязательные функции контракта (собраны из фактических различий):

| Функция                          | Hetzner-реализация                | OVH-реализация                     |
|----------------------------------|-----------------------------------|------------------------------------|
| provider_detect_private_iface    | по IP в PRIVATE_CIDR / MAC 86:00:00 (egress) | по IP в PRIVATE_CIDR   |
| provider_private_gateway         | .1 из CIDR (python)               | ip route show → fallback .1 (готовая resolve_private_gateway из ovh/common.sh) |
| provider_route_mode              | "hetzner-32" (гейтвей /32, onlink) | "ovh-dhcp" (BASTION_PRIVATE_IP)   |
| provider_configure_private_nic   | configure_bastion_private_if + EGRESS_PRIVATE_IP self-config | no-op |
| provider_find_data_volume        | by-id linux-scsi (h-вариант find_db_volume_device) | by-id + QEMU-serial + lsblk fallback (o-вариант) |
| provider_volume_wait_defaults    | echo "45 2"                       | echo "360 5"                       |
| provider_metadata_get            | curl 169.254.169.254 (hetzner)    | OpenStack metadata                 |
| provider_wg_snat_default         | false                             | true                               |

Упаковщик: в `package-bootstrap.sh` добавить в каждый архив
`providers/${PROVIDER}/adapter.sh` (переменная `BOOTSTRAP_PROVIDER`), файл кладётся как
`adapter.sh`. Никакого другого провайдера в архиве.

### Этап 2 — bootstrap/common.sh → route-логика на адаптер

| Что                                   | Куда                                          |
|---------------------------------------|-----------------------------------------------|
| генератор infrazero-private-route.sh (h/o почти идентичны, python-heredoc'и совпадают) | common-base.sh: infrazero_install_private_route_service, gateway берёт из adapter |
| генератор infrazero-wg-route.sh       | common-base.sh: infrazero_install_wg_route_service (route via adapter gateway; при route_mode=none — no-op) |
| resolve_private_gateway (ovh/common.sh) | в adapter ovh (уже его место по контракту)  |
| хвост hetzner/ovh common.sh           | общий common/common-system.sh; provider common.sh становится обёрткой ≤20 строк, как node1.sh |

Итог этапа: `bootstrap/{hetzner,ovh}/common.sh` — тонкие обёртки.

### Этап 3 — db.sh (наибольший выигрыш: 2×2800 → ~2450 common + 2×40)

Создать `bootstrap/common/common-db.sh` из hetzner/db.sh (эталон), с правками:

| Различие                           | Решение                                        |
|------------------------------------|------------------------------------------------|
| find_db_volume_device / find_volume_device | удалить из common; вызывать provider_find_data_volume |
| wait_for_db_volume_device тайминги | дефолты из provider_volume_wait_defaults; env-override оставить |
| max_wal_senders                    | взять OVH-вариант `${DB_MAX_WAL_SENDERS:-10}` — statically-safe для Patroni DCS (не зависит от replica_count, нет pending_restart при добавлении реплик); задокументировать |
| комментарии                        | взять более точные ovh-формулировки            |

`bootstrap/{hetzner,ovh}/db.sh` → обёртки exec common-db.sh. `db-patroni.sh` влить в
common-db.sh (или оставить отдельным — он уже в архиве обеих ролей; решить при
реализации, но не держать два источника pg_hba).
package-bootstrap.sh: role db → common-db.sh + adapter.sh.

### Этап 4 — bastion.sh

Создать `bootstrap/common/common-bastion.sh`:

| Блок                                    | Куда                                     |
|-----------------------------------------|-------------------------------------------|
| sysctl forwarding, общие iptables FORWARD/INPUT primitives, SSH listen, WG peers (уже в common-base) | common-bastion.sh |
| FORWARD private→WG: h — stateful (RELATED,ESTABLISHED), o — stateless | взять stateful (h, безопаснее); флаг на откат |
| WG_SNAT_ENABLED default (h=false, o=true) | default из provider_wg_snat_default     |
| targeted Loki SNAT :3100 (h-only)       | в common под флагом BASTION_TARGETED_LOKI_SNAT (h=true через adapter) |
| configure_bastion_private_if (h-only)   | provider_configure_private_nic в adapter hetzner |
| rp_filter all=0 (o-only)                | в common (безвредно на h)                |

### Этап 5 — egress.sh остатки

| Блок                                   | Куда                                       |
|----------------------------------------|--------------------------------------------|
| _find_private_if по MAC 86:00:00 + fallback + EGRESS_PRIVATE_IP self-config (h) | adapter hetzner |
| single-iface/Floating IP поведение (o) | adapter ovh                                |
| Loki/Grafana блок (Codex отложил сам: большой dashboard-heredoc, в обоих облаках почти идентичен) | common-egress.sh, отдельным атомарным шагом |
| Infisical+Postgres+Redis секция (стр.~540) | уже соответствует common; перенести остаток при выносе Loki/Grafana |

Цель: `{hetzner,ovh}/egress.sh` ≤ ~100 строк каждая (детект NIC + вызовы).

### Этап 6 — beacon fallback дедуп

Fallback-реализация beacon_status продублирована 4 раза: hetzner/common.sh,
ovh/common.sh, hetzner/beacon.sh, ovh/beacon.sh. Оставить одну — в
common-beacon.sh уже есть основная; fallback вынести в крошечный
common/common-beacon-fallback.sh либо генерить в обёртке из одного источника.

### Этап 7 — tofu

| Файл                    | Действие                                                       |
|-------------------------|----------------------------------------------------------------|
| templates/cloud-init.tftpl | один общий шаблон в tofu/modules/cloud-init/; ОБЯЗАТЕЛЬНО перенести в него hetzner-обработку ошибок (set +e, rc, mark_bootstrap_script_failed, retry download) — OVH сейчас без неё; провайдер-вставки через параметры шаблона |
| cloud-init.tf (189/214 общие) | рендер в модуль tofu/modules/cloud-init; известные диффы параметризовать: egress_env ± EGRESS_PRIVATE_IP (передавать extra_egress_env), node_role_env ± pgbouncer_env_lines |
| variables.tf            | 46 общих переменных → variables-common.tf (генератор копирует в каждый provider-каталог из одного источника, т.к. tofu не умеет include); hetzner-only: hcloud_token, network_zone; ovh-only: 9 openstack/ovh_* + server_image_regex → variables-provider.tf |
| locals.tf (72/91 общие) | общую часть (env_lines сборки) — в модуль cloud-init             |
| outputs.tf              | зафиксировать единый контракт: 8 общих outputs + добавить в hetzner отсутствующие db_private_ipv4, egress_private_ipv4, node1_private_ipv4 (приложение тогда одинаково читает outputs на всех облаках) |
| main.tf                 | НЕ объединять. Это и есть «провайдерская» часть                 |
| versions.tf, migrations.tf | оставить как есть                                            |
| bootstrap-artifacts-state.tf (10/12 общие) | в модуль или оставить — мелочь           |

### Этап 8 — scripts

| Файл                          | Действие                                                   |
|-------------------------------|------------------------------------------------------------|
| hetzner/gitops-preflight.sh   | 0 упоминаний провайдера — ПЕРЕНЕСТИ в scripts/common/; убрать «skip если не hetzner» из build.yml (проверить: gate выглядит ошибкой размещения, GitOps не зависит от облака) |
| {h,o}/import-ssh-keys.py      | общий каркас scripts/common/import-ssh-keys.py (парсинг config, дедуп, лейблы) + provider-модуль (hetzner API / openstack keypair) |
| {h,o}/destroy-without-volume.sh | общий драйвер + provider-файл со списком ресурсов/префиксов destroy-order |
| {h,o}/import-volume.sh        | общий драйвер + provider lookup (hcloud-volume-id.sh / openstack show) |
| ovh/cleanup-openstack.sh      | остаётся ovh; УБРАТЬ захардкоженные project/user дефолты (флаг Codex #10) |
| ovh/nuke-all.sh               | остаётся ovh                                                |
| hetzner/hcloud-volume-id.sh   | остаётся hetzner (вызывается из общего import-volume)      |
| common/*                      | уже общие; в render-config.py добавить валидацию cloud_provider ∈ {hetzner,ovhcloud,aws,...} |

### Этап 9 — workflows

| Что                              | Действие                                                |
|----------------------------------|---------------------------------------------------------|
| блок «Determine cloud provider» (6 копий; 4 байт-в-байт, build/rebuild-bastion слегка отличаются — сначала выяснить чем) | composite action .github/actions/select-provider: вход cloud_provider+region, выход TOFU_DIR/SCRIPTS_DIR/BOOTSTRAP_DIR/BOOTSTRAP_PROVIDER + экспорт TF_VAR_* провайдера |
| rebuild-{bastion,db,db-replica,egress,nodes}.yml — копии друг друга на ~90% | один reusable workflow rebuild-role.yml с input role; тонкие триггер-файлы |
| provider-secrets                 | внутрь composite action; новое облако = +ветка в одном месте, а не в 6 файлах |

### Этап 10 — selective copy пользователю (phase 6 Codex)

Генератор (scripts/common/materialize-user-repo.sh): копирует
`bootstrap/common + bootstrap/providers/<X> + tofu/<X> + tofu/modules + scripts/common +
scripts/<X> + .github + config + README`. Требование к этапам 1–9: после них ни один
общий файл не ссылается на путь другого провайдера, поэтому копия собирается тривиально.
CI-проверка: materialize для каждого провайдера + full dry-package из материализованной
копии + grep-запрет упоминаний чужого провайдера.

## Что НЕ объединять (фиксируем)

tofu main.tf (hcloud_* / openstack_*), versions.tf; MAC-детект Hetzner; Floating IP
OVH; cleanup/nuke OpenStack; volume discovery (уходит в адаптеры, не в common);
provider-креды в workflows (уходят в composite action, но остаются провайдерскими).

## Порядок и зависимости

1 (adapter) → 2 (common.sh) → 3 (db) → 4 (bastion) → 5 (egress) → 6 (beacon) —
bootstrap-цепочка, каждый этап атомарный PR со своим rebuild-тестом на staging.
7 (tofu) и 8 (scripts) независимы от 1–6, можно параллельно. 9 (workflows) после 8.
10 — последним. AWS начинать только после 10: тогда он = adapter.sh + tofu/aws +
scripts/aws + ветка в select-provider.

## Обязательные проверки каждого этапа

bash -n + shellcheck всех затронутых; dry-package всех 8 ролей обоих облаков; tar-лист
каждого архива (нет чужого провайдера, есть adapter.sh); tofu validate обоих; после
этапов 2–5 — реальный rebuild соответствующей роли на staging обоих облаков (bash -n не
ловит поведение); git diff --check.

## Ожидаемый итог по объёму (bootstrap)

Сейчас: ~4900 строк в common + ~8500 в двух провайдерах. После этапов 1–6:
~7800 в common + ~2×400 провайдерских (адаптер + обёртки + NIC-специфика egress).
Добавление AWS: ~400–600 строк (adapter.sh + tofu/aws main) вместо ~8500 копий.
