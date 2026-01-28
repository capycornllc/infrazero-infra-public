#!/usr/bin/env bash
set -euo pipefail

echo "[db] $(date -Is) starting volume mount"

MOUNT_DIR="/mnt/db"
VOLUME_NAME="${DB_VOLUME_NAME:-}"
VOLUME_FORMAT="${DB_VOLUME_FORMAT:-ext4}"
DEVICE=""

if [ -n "$VOLUME_NAME" ] && [ -e "/dev/disk/by-id/scsi-0HC_Volume_${VOLUME_NAME}" ]; then
  DEVICE="/dev/disk/by-id/scsi-0HC_Volume_${VOLUME_NAME}"
else
  candidate=$(ls -1 /dev/disk/by-id/scsi-0HC_Volume_* 2>/dev/null | head -n 1 || true)
  if [ -n "$candidate" ]; then
    DEVICE="$candidate"
  else
    candidate=$(ls -1 /dev/disk/by-id/*Volume* 2>/dev/null | head -n 1 || true)
    if [ -n "$candidate" ]; then
      DEVICE="$candidate"
    fi
  fi
fi

if [ -z "$DEVICE" ]; then
  echo "[db] no attached volume device found; skipping mount"
  exit 0
fi

mkdir -p "$MOUNT_DIR"

if ! blkid "$DEVICE" >/dev/null 2>&1; then
  echo "[db] formatting $DEVICE as $VOLUME_FORMAT"
  mkfs -t "$VOLUME_FORMAT" "$DEVICE"
fi

UUID=$(blkid -s UUID -o value "$DEVICE" || true)
if [ -z "$UUID" ]; then
  echo "[db] unable to determine UUID for $DEVICE" >&2
  exit 1
fi

if ! grep -q "$UUID" /etc/fstab; then
  echo "UUID=$UUID $MOUNT_DIR $VOLUME_FORMAT defaults,nofail 0 2" >> /etc/fstab
fi

if ! mountpoint -q "$MOUNT_DIR"; then
  mount "$MOUNT_DIR" || mount -a
fi

echo "[db] $(date -Is) volume mount complete"
