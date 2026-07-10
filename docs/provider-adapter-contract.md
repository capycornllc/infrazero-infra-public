# Контракт провайдер-адаптера

Дата: 2026-07-10. Реализует этап 1 плана `file-unification-plan.md`.

Каждое облако описывается одним файлом `bootstrap/providers/<provider>/adapter.sh`.
Общие скрипты (`bootstrap/common/*`) не содержат ни одного провайдер-ветвления —
всю специфику они получают из функций адаптера. Новое облако (AWS, Azure, GCP) =
новый `adapter.sh` + `tofu/<provider>` + `scripts/<provider>`; общие скрипты не
меняются.

## Как адаптер попадает к скриптам

- В каждый bootstrap-архив упаковщик (`scripts/common/package-bootstrap.sh`)
  кладёт `providers/${BOOTSTRAP_PROVIDER}/adapter.sh` плоско как `adapter.sh`.
  `BOOTSTRAP_PROVIDER` по умолчанию — basename `BOOTSTRAP_DIR`. Чужой адаптер в
  архив не попадает никогда.
- Общие скрипты загружают его через `infrazero_load_provider_adapter`
  (в `common-base.sh`): сначала `adapter.sh` рядом со скриптом (архив), затем
  `bootstrap/providers/${INFRAZERO_PROVIDER}/adapter.sh` (репозиторий; переменную
  экспортируют провайдер-обёртки). Если адаптер не найден — жёсткая ошибка:
  угадывать облако нельзя.
- Адаптер только объявляет функции `provider_*` и экспортирует
  `INFRAZERO_PROVIDER`. Никаких побочных действий при source.

## Обязательные функции

| Функция | Сигнатура | Семантика |
|---|---|---|
| `provider_route_mode` | `-> строка` | Режим маршрутизации: `hetzner-32` (гостям выдаются /32 NIC: явный gateway, onlink, ремонт default route, WG-маршрут через gateway), `ovh-dhcp` (NIC настраивает DHCP; WG-маршрут через `BASTION_PRIVATE_IP`), `none` (облако маршрутизирует само, route-скрипты — no-op; задел под AWS VPC). |
| `provider_private_gateway [cidr]` | `-> IPv4` | Шлюз приватной сети. По умолчанию `cidr=$PRIVATE_CIDR`. Hetzner: первый адрес CIDR. OVH: из `ip route` (DHCP), fallback — первый адрес CIDR. |
| `provider_detect_private_iface [cidr]` | `-> имя NIC` | Интерфейс с IPv4 внутри приватного CIDR. Hetzner дополнительно ищет по MAC-префиксу `86:00:00` (работает до назначения IP; вернувшийся интерфейс может быть ещё без адреса). |
| `provider_configure_private_nic <ipv4>` | `-> 0` | Донастроить приватный NIC, если облако не успело (гонка cloud-init). Hetzner: назначить `<ipv4>/32` и починить маршруты. OVH: no-op (DHCP делает всё сам). Всегда возвращает 0. |
| `provider_find_data_volume [name]` | `-> путь /dev/...` | Блок-устройство приклеенного data-тома. Hetzner: by-id `HC_Volume`. OVH: by-id + fallback на первый несмонтированный диск (QEMU serial). Возврат 1, если не найден. |
| `provider_volume_wait_defaults` | `-> "attempts sleep"` | Дефолты ожидания attach тома. Hetzner: `45 2`. OVH: `360 5`. Переопределяются `DB_VOLUME_ATTACH_WAIT_ATTEMPTS/SECONDS`. |
| `provider_wg_snat_default` | `-> true\|false` | Дефолт SNAT WG-трафика на bastion. Hetzner: `false` (сеть маршрутизирует WG-подсеть). OVH: `true` (OpenStack-роутер не знает WG-подсеть). |
| `provider_metadata_get <key>` | `-> значение` | Best-effort чтение instance metadata (169.254.169.254). |
| `provider_egress_setup_interfaces` | `устанавливает PUBLIC_IF/PRIVATE_IF` | Детект интерфейсов для egress-роли; 1 = не найдены. Hetzner: MAC-префикс `86:00:00` + ожидание + self-config c systemd-networkd. OVH: IP-in-CIDR; single-interface режим Floating IP (PRIVATE_IF может равняться PUBLIC_IF). |

## Необязательные функции

| Функция | Семантика |
|---|---|
| `provider_outbound_defaults` | Экспортирует дефолты `INFRAZERO_OUTBOUND_*` / `INFRAZERO_PUBLIC_IPV4_*` для ожидания исходящей связности в `infrazero_install_base_packages`. Уже установленные значения окружения не перетираются. Если функции нет — работают дефолты `common-base.sh`. |

## Правила для общих скриптов

1. Общий скрипт вызывает `infrazero_load_provider_adapter` до первого
   использования `provider_*`.
2. Сгенерированные runtime-скрипты (например `/usr/local/sbin/infrazero-*-route.sh`)
   не могут звать адаптер: провайдер-выбор запекается в них при генерации
   (например `INFRAZERO_ROUTE_MODE`), а всё, что должно резолвиться на каждом
   запуске (шлюз при DHCP), реализуется универсальным кодом внутри
   сгенерированного скрипта.
3. Упоминание имени конкретного облака в `bootstrap/common/*` — ошибка ревью,
   кроме комментариев-примеров.

## Чек-лист нового облака

Шаблон адаптера: `bootstrap/providers/_template/adapter.sh.template`; для
aws/azure/gcp есть заготовки с инструкцией (`bootstrap/providers/<cloud>/README.md`).

1. `bootstrap/providers/<новый>/adapter.sh` — все обязательные функции.
2. `tofu/<новый>/` — main.tf и провайдер-переменные.
3. `scripts/<новый>/` — provider API (volume lookup, cleanup).
4. Ветка провайдера в workflows (после этапа 9 — одно место: composite action).
5. Прогнать: dry-package всех ролей, tar-лист (есть `adapter.sh`, нет чужого
   облака), staging-деплой.
