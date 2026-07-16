# Финальная provider-модель перед AWS

Дата: 2026-07-16. Статус: реализовано для Hetzner и OVHcloud. AWS, Azure и
GCP здесь не реализованы и не считаются поддержанными.

## Итог

Добавление нового облака больше не требует править deploy/rebuild workflow или
добавлять provider-ветку в центральный action. Рабочие Hetzner и OVHcloud
изолированы своими каталогами, а общая часть только проверяет контракт и
подключает выбранную реализацию.

Общие серверные bootstrap-скрипты, безопасность, мониторинг bootstrap-фаз,
упаковка артефактов и retry-механика не менялись в этом последнем этапе.

## Финальная структура

```text
bootstrap/common/                  общая настройка Ubuntu и сервисов
bootstrap/providers/<cloud>/       runtime-адаптер сети, route, volume, metadata
bootstrap/<cloud>/                 тонкие role entrypoints

tofu/common/                       канонические общие Tofu-файлы
tofu/modules/                      общие модули
tofu/<cloud>/                      ресурсы конкретного облака

scripts/common/                    provider-neutral drivers и проверки
scripts/<cloud>/ci-credentials.sh  только credentials/defaults этого cloud
scripts/<cloud>/tofu-resources.sh  адреса ресурсов для build/rebuild
scripts/<cloud>/                   destroy/import/provider API
```

`scripts/common/provider-contract.sh` является единым списком обязательных
entrypoint. Его используют selector, materialize и CI, поэтому их представление
о «полностью реализованном provider» не может разойтись.

## Как выбирается provider

`.github/actions/select-provider/action.yml` — тонкая обёртка. Вся общая логика
лежит в `scripts/common/select-provider.sh`:

1. Нормализует `CLOUD_PROVIDER`.
2. Для исторического имени `ovhcloud` выбирает каталог `ovh`. Стандартные имена
   cloud совпадают с каталогом и центрального mapping не требуют.
3. До `tofu init` проверяет полный provider contract.
4. Публикует `CLOUD_PROVIDER_DIR`, `TOFU_DIR`, `SCRIPTS_DIR`,
   `BOOTSTRAP_DIR`, `BOOTSTRAP_PROVIDER` и канонический
   `CLOUD_PROVIDER_RESOLVED`.
5. Публикует путь к `scripts/<selected>/ci-credentials.sh`; следующий exporter
   вызывает только этот provider entrypoint.

Неизвестный или частично реализованный provider завершается ранней понятной
ошибкой с отсутствующими путями. Он не может случайно провалиться в Hetzner
defaults и дойти до OpenTofu.

## Credentials и безопасность

В shared workflow больше нет прямых ссылок на Hetzner/OVH credentials. Один
exporter читает `toJSON(secrets)` через stdin и за один проход:

- экспортирует только split/legacy Infisical bootstrap payload;
- по контракту выбранного `ci-credentials.sh` отделяет маленький provider JSON;
- передаёт дочернему provider-скрипту только этот выбранный набор.

Полный JSON не попадает в env, не передаётся аргументом процесса, не печатается
и не записывается в отдельный временный файл. Поэтому схема не упирается в
лимит размера одной Linux env-переменной при больших split payload. В
`$GITHUB_ENV` попадают только реально нужные значения.

Эквивалентность старому поведению сохранена:

- Hetzner экспортирует `HCLOUD_TOKEN` и `TF_VAR_hcloud_token`;
- OVHcloud экспортирует прежние `TF_VAR_ovh_*`, `TF_VAR_openstack_*`, сохраняет
  fallback tenant id из project id и прежний выбор US/EU auth endpoint;
- fallback `pgbouncer_server_type` остался `cx23` для Hetzner и `b2-7` для
  OVHcloud, но теперь принадлежит provider-скриптам.

`render-config.py` больше не содержит списка будущих cloud и не выдаёт
неизвестному provider Hetzner flavor.

## Single-cloud репозиторий пользователя

`materialize-user-repo.sh` копирует только:

- общие bootstrap/scripts/tofu modules;
- adapter, wrappers, Tofu root и scripts выбранного cloud;
- shared workflows, config и docs.

Перед завершением он повторно проверяет provider contract, отсутствие каталогов
других cloud и отсутствие прямых provider credential bindings в `.github`.
Таким образом Hetzner-репозиторий не получает OVH runtime/Tofu/scripts, и
наоборот. Shared workflow остаётся один, но не знает полей чужого provider.

UI path filter должен продолжать применять тот же принцип: shared prefixes плюс
каталоги выбранного cloud. Для нестандартного публичного имени допускается только
alias имени (`ovhcloud -> ovh`), не provider-логика.

## CI-защита

`.github/workflows/ci.yml` ничего не разворачивает. Он:

- проверяет shell/Python syntax и shellcheck errors;
- проверяет синхронизацию канонических Tofu common-файлов;
- запрещает provider API/resource tokens в `bootstrap/common`;
- запрещает прямой binding provider credentials в shared workflows;
- проверяет наличие всех обязательных функций bootstrap adapter;
- автоматически находит полностью подключённые provider по
  `scripts/<cloud>/ci-credentials.sh`;
- для каждого найденного cloud делает single-cloud materialize, dry-package
  всех ролей и `tofu validate`.

Новый provider автоматически попадает в матрицу после появления полного
контракта. Если он недоделан или изменение общего слоя ломает Hetzner/OVH, PR
становится красным до merge.

## Что намеренно осталось provider-specific

Нельзя выносить в common:

- OpenTofu resource types и зависимости конкретного API;
- floating IP association OVH;
- Hetzner `/32` NIC/route и OVH DHCP/single-NIC особенности;
- volume discovery и API import/cleanup;
- credential names, auth endpoint и cloud-specific defaults;
- build/rebuild resource addresses и дополнительные targets.

Это не дублирование, а граница provider contract. Попытка сделать эти части
универсальными создаст условные ветки в общем коде и снова свяжет облака.

## Чек-лист нового cloud

До добавления cloud в UI нужно создать и проверить:

1. `bootstrap/providers/<cloud>/adapter.sh` по adapter contract.
2. Тонкие wrappers всех поддержанных ролей в `bootstrap/<cloud>/`.
3. Полный `tofu/<cloud>/` с provider variables и общими synced files.
4. `scripts/<cloud>/ci-credentials.sh` с `--list-secret-names` (список может
   быть пустым для provider, использующего OIDC без static secrets).
5. `scripts/<cloud>/tofu-resources.sh`.
6. Provider destroy/import entrypoints из `provider-contract.sh`.
7. Materialize, dry-package всех ролей и `tofu validate`.
8. Реальный staging build и каждый применимый rebuild/destroy.
9. Только после этого — UI schema, credentials и выбор server types.

## Остаточный риск

Структурные проверки доказывают синтаксис, изоляцию, упаковку и Tofu graph, но
не могут доказать поведение API облака, cloud-init timing, маршруты и floating IP
на реальной площадке. Поэтому перед AWS обязательны последние staging-прогоны
Hetzner и OVHcloud на этой версии selector/workflow. Это единственная оставшаяся
проверка, а не незавершённый архитектурный рефактор.
