# Multi-Database + Per-DB Age Keys Integration (Infra Repo)

This repo is migrated to the multi-database model from the UI:
- App DBs are defined by the `databases_json` GitHub Actions secret.
- Each DB has its own Age keypair for backups (public for encrypt, private for decrypt).
- Infisical DB has its own *dedicated* Age keypair (separate from app DBs).

## Inputs (GitHub Actions secrets)

Required:
- `databases_json`: JSON array of objects with:
  - `name`
  - `user`
  - `password`
  - `backup_age_public_key`
  - `backup_age_private_key`
  - `restore_latest` (optional; default `true`)
  - `restore_dump_path` (optional; used when `restore_latest` is `false`)
- `infisical_db_backup_age_public_key`
- `infisical_db_backup_age_private_key`

Notes:
- Legacy single-db secrets (`app_db_*`, `db_backup_age_*`) are ignored by this repo.
- Duplicate DB users are allowed: DB bootstrap applies "last write wins" for role password.

## S3 Layout

App DB backups (per-db only):
- Dump: `db/<db_name>/<timestamp>.sql.gz.age`
- Manifest: `db/<db_name>/latest-dump.json`

Infisical DB backups:
- Dump + manifest continue to live under `infisical/` (separate from app DBs).

## DB Server Bootstrap

`bootstrap/db.sh`:
- Creates/updates all roles and DBs listed in `DATABASES_JSON` (from `/etc/infrazero/db.env`).
- Restores latest backups automatically *only on a fresh cluster*:
  - Uses `DATABASES_JSON_PRIVATE_B64` (base64 of full `databases_json`, including private keys) passed via cloud-init.
  - For each DB:
    - When `restore_latest` is `true` (default), fetches `db/<db_name>/latest-dump.json` and restores the referenced object.
    - When `restore_latest` is `false`, restores from `restore_dump_path` (or skips restore if it is empty/missing).
  - Drops and recreates each DB before restoring.
  - Unsets `DATABASES_JSON_PRIVATE_B64` and scrubs its export line in `/opt/infrazero/bootstrap/run.sh` after restore.
- Installs:
  - `/opt/infrazero/db/backup.sh`: backs up all DBs, encrypting each dump with that DB's public key, and writes per-db manifests.
  - `/opt/infrazero/db/restore.sh`: manual restore for a single DB.

## Manual DB Restore

Run on the DB server:
`sudo /opt/infrazero/db/restore.sh <db_name> <s3-key-or-s3-url>`

Behavior:
- Requires explicit DB name + explicit backup key/url.
- Never formats the volume.
- Drops and recreates the target DB only.
- If the dump is Age-encrypted, prompts for the Age private key.

## Infisical Changes

- Infisical DB backups are encrypted/decrypted using:
  - `INFISICAL_DB_BACKUP_AGE_PUBLIC_KEY` (encrypt)
  - `INFISICAL_DB_BACKUP_AGE_PRIVATE_KEY` (decrypt)
- Infisical admin token stored in S3 is also encrypted/decrypted with the Infisical DB Age keypair.

## Quick Validation

Local:
- `python -m py_compile scripts/render-config.py`
- `python scripts/validate-config.py --config config/infra.yaml --schema config/schema.json`

Repo-wide sanity checks:
- Ensure no remaining runtime dependencies on `APP_DB_*` or `DB_BACKUP_AGE_*`.
