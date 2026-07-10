# aws: заготовка провайдера

Ветка в CI уже существует (`.github/actions/select-provider`, CLOUD_PROVIDER=aws).
Чтобы включить облако, нужно добавить:

1. `bootstrap/providers/aws/adapter.sh` — скопировать
   `bootstrap/providers/_template/adapter.sh.template` и реализовать все
   функции контракта (`docs/provider-adapter-contract.md`).
2. `bootstrap/aws/` — тонкие обёртки ролей (копия `bootstrap/hetzner/` —
   там уже только обёртки по ~19 строк; заменить имя провайдера).
3. `tofu/aws/` — main.tf (ресурсы облака), versions.tf,
   variables-provider.tf (креды/flavor/image), outputs.tf (8 общих outputs),
   cloud-init.tf (вызов `tofu/modules/cloud-init` — скопировать у hetzner/ovh
   и поправить route_mode/extra_*); variables-common.tf синхронизируется
   `scripts/common/sync-tofu-common.sh`.
4. `scripts/aws/` — import-ssh-keys.py (каркас:
   `scripts/common/import_ssh_keys_common.py`), destroy-without-volume.sh
   (каркас: `destroy-without-volume-driver.sh` + списки префиксов),
   import-volume.sh + volume-id.sh (каркас: `import-volume-driver.sh`).
5. Креды TF_VAR_* — в ветку aws в `.github/actions/select-provider/action.yml`.

Проверка: `scripts/common/materialize-user-repo.sh aws /tmp/test-aws` +
dry-package всех ролей из копии (команда в выводе materialize).

Общие скрипты (`bootstrap/common`, `tofu/modules`, `scripts/common`) менять
НЕ нужно — в этом смысл адаптера.
