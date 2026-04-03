# Полный аудит infrazero-infra-public и infrazero-gitops-public

## КРИТИЧЕСКИЕ БАГИ (ломают bootstrap)

### 1. ✅ ИСПРАВЛЕНО: `beacon_status: command not found` — cloud-init.tftpl
**Файлы:** `tofu/templates/cloud-init.tftpl`, `tofu/ovh/templates/cloud-init.tftpl`
**Проблема:** `run.sh` запускал `./common.sh` и `./$ROLE.sh` как отдельные процессы. Функция `beacon_status()` определена в `common.sh`, но недоступна в role-скриптах при запуске как subprocess.
**Результат:** Все серверы падают на первом вызове `beacon_status` в role-скрипте. WireGuard не устанавливается, bootstrap застревает на 80%.
**Исправление:** Заменено на `source ./common.sh` и `source "./$ROLE.sh"`.

### 2. Двойной `exec > >(tee ...)` при source
**Файлы:** Все `bootstrap/*.sh`
**Проблема:** Каждый скрипт делает `exec > >(tee -a "$LOG_FILE") 2>&1`. При `source` это создаёт вложенные process substitutions — каждый `source` добавляет ещё один `tee` в цепочку. Может привести к потере вывода или дублированию строк.
**Рекомендация:** Убрать `exec > >(tee ...)` из role-скриптов — `common.sh` уже настраивает redirect. Или добавить guard: `if [ -z "${_INFRAZERO_LOG_REDIRECTED:-}" ]; then exec > >(tee -a "$LOG_FILE") 2>&1; export _INFRAZERO_LOG_REDIRECTED=1; fi`

### 3. `exit` в role-скриптах при source
**Файлы:** `pgbouncer.sh` (exit 0 на строке 210), `infisical-bootstrap.sh` (exit 0 на строке 13)
**Проблема:** При `source` `exit 0` завершает весь shell (run.sh), а не только скрипт. `pgbouncer.sh` line 210: `exit 0` при "no DB hosts configured" — завершит run.sh успешно, cloud-init не увидит ошибку.
**Рекомендация:** Заменить `exit` на `return` в role-скриптах, или оставить `./` вместо `source` и экспортировать `beacon_status` через отдельный файл.

## ВЫСОКИЙ ПРИОРИТЕТ

### 4. Нет таймаута на bootstrap скрипты
**Файлы:** `tofu/templates/cloud-init.tftpl`
**Проблема:** `run.sh` не имеет общего таймаута. Если скрипт зависнет (например, ожидание apt lock), cloud-init будет ждать бесконечно.
**Рекомендация:** Добавить `timeout 3600` перед source скриптов.

### 5. `db.sh` — нет проверки монтирования volume
**Файл:** `bootstrap/db.sh`
**Проблема:** Скрипт монтирует volume но не проверяет что mount успешен перед записью данных.
**Рекомендация:** Добавить `mountpoint -q "$MOUNT_DIR" || exit 1` после mount.

### 6. `node1.sh` — kubectl download без проверки версии
**Файл:** `bootstrap/node1.sh`
**Проблема:** K3s устанавливается с retry, но нет проверки что установленная версия совместима с конфигурацией.

### 7. GitHub Actions — секреты в environment variables
**Файл:** `.github/workflows/build.yml`
**Проблема:** Все секреты экспортируются как env vars в job level. Любой step имеет доступ ко всем секретам. Если один step скомпрометирован — все секреты утекают.
**Рекомендация:** Передавать секреты только в steps которые их используют.

## СРЕДНИЙ ПРИОРИТЕТ

### 8. `monitor-bootstrap.sh` — hardcoded server list
**Файл:** `scripts/monitor-bootstrap.sh`
**Проблема:** Список серверов строится из tofu outputs, но не включает pgbouncer, db-replica, nodecp, node2.

### 9. `egress.sh` — Infisical bootstrap race condition
**Файл:** `bootstrap/egress.sh`
**Проблема:** `infisical-bootstrap.sh` запускается в фоне, но основной скрипт не ждёт его завершения. Если bootstrap упадёт — ошибка не будет замечена.

### 10. `bastion.sh` — WG peer config без валидации
**Файл:** `bootstrap/bastion.sh`
**Проблема:** `WG_ADMIN_PEERS_JSON` парсится через jq без валидации формата. Невалидный JSON приведёт к пустому WG конфигу.

## GITOPS РЕПОЗИТОРИЙ

### 11. Placeholder значения не заменены
**Файлы:** Множество файлов в `platform/`, `clusters/`, `config/`
**Проблема:** `REPLACE_ME`, `your-org/your-repo`, `example.com`, `PGBOUNCER_IP_PLACEHOLDER` — эти значения должны заменяться при деплое, но нет автоматизации для проверки.
**Рекомендация:** Добавить CI check что placeholder'ы заменены.

### 12. ArgoCD Project — overly permissive RBAC
**Файлы:** `clusters/*/project.yaml`
**Проблема:** `clusterResourceWhitelist: group: "*", kind: "*"` — разрешает всё. В production нужно ограничить.

### 13. Нет network policies
**Проблема:** Все workloads могут общаться друг с другом без ограничений.

### 14. cert-manager — hardcoded email
**Файл:** `platform/cert-manager/cluster-issuers.yaml`
**Проблема:** `email: admin@example.com` — не заменяется автоматически.
