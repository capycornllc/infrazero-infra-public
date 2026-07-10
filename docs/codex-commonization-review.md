# Ревью коммонизации Codex (Hetzner/OVH → common) и план под AWS/Azure/GCP

Дата: 2026-07-10. Проверено против оригинала в `Orginal working logic/infrazero-infra-public`.

## Как проверялось

`bash -n` по всем shell-файлам; реальный dry-run упаковки всех 8 ролей для Hetzner и OVH с
проверкой состава архивов; функциональное сравнение — каждая функция из оригинальных
provider-скриптов найдена либо в common-версии, либо заменена на `infrazero_*`-аналог;
построчное сравнение db.sh/common.sh/bastion.sh/egress.sh с оригиналами; проверка
cloud-init шаблонов и workflow.

## Вердикт

Работа сделана добротно. Логика не потеряна: все функции оригиналов либо перенесены,
либо осознанно заменены общими helper'ами (`load_env`→`infrazero_load_env_file`,
`require_env`→`infrazero_require_env`, `retry`→`infrazero_retry`,
`detect_private_iface`→`infrazero_detect_private_iface`). Спорные различия между
облаками слиты аккуратно: OVH-only `setup_etcd_patroni` сохранён под флагом
`ETCD_PATRONI_ENABLED`, hetzner-only `wait_for_k3s_primary_api` сохранён в
`common-node-agent.sh`, у pgbouncer взят более безопасный OVH-вариант watcher'а
(фильтр реплик по `state==running/streaming`). Контракты не сломаны: S3-путь
`bootstrap/${role}.tar.zst`, форма manifest, `/opt/infrazero/bootstrap` — без изменений.

## Что сделано хорошо

Правильный принцип границы: common = сервисная логика одинаковая на любом Ubuntu,
provider = NIC/route/volume/metadata. Различия Hetzner/OVH выражены параметрами, а не
ветвлениями `if provider`: например outbound-wait (Hetzner: mirror.hetzner.com, 300×5s,
degraded beacon; OVH: autodetect public IPv4, 90×2s) — один helper
`infrazero_install_base_packages` с env-настройками. OVH-only поведение Infisical
вынесено в явные флаги `INFISICAL_ALLOW_INTERNAL_IP_CONNECTIONS` /
`INFISICAL_KUBERNETES_EXTRA_HOSTS` с default=false — AWS/Azure/GCP не унаследуют его
случайно. Это ровно та модель, которую стоит продолжать.

Фикс pg_hba правильный: явные `127.0.0.1/32` + `${PRIVATE_CIDR}` вместо случайного
покрытия через `0.0.0.0/0` у Hetzner; общий шаблон в `db-patroni.sh` не даст облакам
снова разъехаться. `package-bootstrap.sh` валидирует наличие файлов, кладёт в архив
только нужную роль + common, чужой провайдер в архивы не попадает (проверено на обоих
облаках). Обёртки `role.sh → exec common-role.sh` с fallback-путём — простые и
предсказуемые. План-документ `infra-cloud-commonization-plan.md` качественный, его
целевая структура (common/lib + common/roles + providers/<cloud>/adapter) верная.

## Найденные проблемы

1. CRLF (ИСПРАВЛЕНО). `bootstrap/hetzner/egress.sh` был с CRLF-окончаниями — `bash -n`
   на нём падал с syntax error. На серверах спасал `sed -i 's/\r$//'` в cloud-init, но
   это мина: любой новый исполняемый файл вне cloud-init-очистки сломается. Исправил
   файл и добавил `.gitattributes` (`*.sh text eol=lf` и т.д.) — корневая причина закрыта.

2. Неконсистентный beacon-guard. В `common-base.sh` `infrazero_install_base_packages`
   вызывает `beacon_status` без проверки `declare -F` (строка ~184), хотя все остальные
   вызовы обёрнуты. При ручном запуске role-скрипта по SSH (без экспортированных из
   cloud-init функций) скрипт упадёт под `set -e`. Обернуть так же, как остальные.

3. Дубли внутри самого common-base.sh: `infrazero_install_wireguard_packages` (свой цикл
   20×10s) и `infrazero_ensure_aws_cli` (свой apt-фоллбек) не используют
   `infrazero_apt_get`/`infrazero_retry`. Fallback-реализация `beacon_status` скопирована
   в 4 места (hetzner/ovh `common.sh` + обе обёртки `beacon.sh`) — при следующем правиле
   редактирования разъедутся.

4. `infrazero_ensure_aws_cli` качает только `awscli-exe-linux-x86_64.zip`. На AWS
   Graviton/Azure arm64 сломается. Нужен выбор архива по `uname -m` (x86_64 | aarch64) —
   лучше поправить до, а не после появления Амазона.

5. Два разных сентинеля лог-редиректа: `_INFRAZERO_LOG_REDIRECTED` (common.sh,
   common-node1.sh) и `INFRAZERO_LOG_REDIRECTED` (db.sh, pgbouncer). Работает, потому что
   каждый процесс редиректит сам, но это ловушка на будущее — привести к одному имени.

6. OVH cloud-init шаблон отстаёт от Hetzner: `./common.sh` и `./$ROLE.sh` запускаются
   без `set +e`/захвата rc/`mark_bootstrap_script_failed`. При падении роли OVH-нода не
   репортит структурированную причину. Шаблоны на 90% идентичны (230 общих строк из
   258) — это следующий кандидат на общий шаблон, и выравнивание error handling должно
   войти в него.

7. Поведенческое изменение pgbouncer для Hetzner: раньше read-pool мог сразу стартовать
   на `DB_REPLICA_HOSTS`, теперь всегда стартует на primary, а watcher переносит на
   реплики после подтверждения их состояния. Решение обоснованное (безопаснее), но это
   изменение поведения относительно «эталонного» Hetzner — стоит знать при первом
   rebuild pgbouncer.

8. Мелочи: маппинг role→файлы в `package-bootstrap.sh` — хардкод if-цепочка (при 5
   облаках и росте ролей лучше декларативная таблица); имя архива всегда `.tar.zst`
   даже при `PACKAGE_BOOTSTRAP_COMPRESSION=none`.

## Что реально ещё объединять (по измеренным данным)

`db.sh` — главный оставшийся дубль: 2413 идентичных строк из ~2800 (87%). План Codex
(вынести postgres/patroni/backup-restore/volume-discovery-адаптер) верен, и его
рекомендация начинать с DB — правильная. `bastion.sh`: 333 общих строки из ~430-500
(sysctl forwarding, iptables primitives, SSH listen — common; SNAT/route-режимы —
provider). `common.sh`: 290 общих строк — оба route-repair скрипта почти идентичны
(python-heredoc'и совпадают дословно); генераторы скриптов вынести в common, провайдеру
оставить только выбор gateway/route-режима, `resolve_private_gateway` из OVH — готовый
кандидат в общий helper. `cloud-init.tftpl` — фактически один шаблон на двоих.
Fallback beacon — в одно место. Egress уже разделён хорошо (75 общих строк — остаток
это осознанная специфика NIC/Floating IP).

Не объединять (согласен с Codex): tofu-ресурсы провайдеров, MAC-детект Hetzner,
OpenStack-очистка OVH, volume discovery. Общим должен быть только контракт.

## Как построить идеальную систему под AWS/Azure/GCP

Целевая структура Codex верна; главное, чего в ней не хватает — формализованного
контракта адаптера. Предлагаю зафиксировать файлом `docs/provider-adapter-contract.md`
и conformance-тестом (скрипт source'ит adapter и проверяет `declare -F`):

```text
bootstrap/
  common/
    lib/            # apt, env, beacon, ssh, promtail, postgres, patroni, k3s, ...
    roles/          # common, bastion, egress, db, db-replica, pgbouncer, node*, infisical-*
  providers/
    hetzner|ovh|aws|azure|gcp/
      adapter.sh    # реализует ровно контракт, ничего больше
tofu/
  hetzner|ovh|aws|azure|gcp/   # свой main.tf, но одинаковые roles/env/outputs/manifest
```

Минимальный контракт адаптера (обязательные функции):
`provider_detect_private_iface`, `provider_private_gateway`, `provider_route_mode`
(hetzner-32 | ovh-dhcp | none), `provider_configure_private_nic`,
`provider_find_data_volume` (device по имени/тегу), `provider_metadata_get`.

Специфика будущих облаков, которую контракт обязан покрыть уже сейчас (иначе придётся
ломать API адаптера): AWS — NVMe-имена дисков (/dev/nvme1n1, поиск по serial vol-xxx),
IMDSv2 metadata с токеном, source/dest-check для NAT-egress выключается на уровне tofu,
route repair не нужен (`route_mode=none` — VPC роутит сам), arm64. Azure — диски по LUN
(/dev/disk/azure/scsi1/lunX), NSG вместо iptables-логики на уровне облака. GCP — диски
/dev/disk/by-id/google-<name>, metadata server, MTU 1460. Всё это ложится в три функции
контракта (iface, volume, metadata) плюс `route_mode=none` — значит контракт достаточен,
и «новый клауд = один adapter.sh + свой tofu/<cloud>».

Копирование пользователю только своего облака (phase 6 у Codex): генератор тривиален —
`common/ + providers/<выбранный>/ + tofu/<выбранный>/ + scripts/common/ +
scripts/<выбранный>/ + workflows`. Единственное реальное препятствие: workflow'ы сейчас
содержат if-ветки обоих провайдеров (secrets, preflight). Провайдер-специфику из yml
вынести в `scripts/<provider>/preflight.sh` с единым интерфейсом — тогда workflow
одинаков для всех и копируется как есть.

## Рекомендуемый порядок (до начала AWS)

1. Мелкие фиксы из ревью: beacon-guard, aws-cli arch по uname -m, один сентинель
   лог-редиректа, дедуп fallback-beacon (CRLF/.gitattributes уже сделаны).
2. Adapter skeleton + контракт + conformance-тест; перевести route-логику
   hetzner/ovh common.sh на адаптеры. Это фиксирует API до появления третьего облака.
3. DB commonization по плану Codex (наибольший выигрыш, 87% дублей).
4. Остатки bastion; общий cloud-init.tftpl с выравниванием OVH error handling.
5. CI-гейт: shellcheck + bash -n + dry-package всех провайдеров + проверка «в архиве
   нет чужого провайдера» (Codex делает это руками — автоматизировать).
6. Phase 6 (selective repo output) + рефактор workflow.
7. Только после этого — AWS: пишется один adapter.sh + tofu/aws по контракту.

После каждой фазы — реальный rebuild на staging обоих облаков: bash -n и dry-package
не ловят поведение, а db/patroni-изменения применяются только при re-bootstrap.
