#!/usr/bin/env sh
set -eu

if [ "${CONFIRM:-}" != "YES" ]; then
  echo "Refusing destructive ZK cutover."
  echo "Run: CONFIRM=YES BACKUP=backups/<file>.sql.gz make cutover-zk"
  exit 1
fi

backup="${BACKUP:-}"
if [ -z "$backup" ] || [ ! -s "$backup" ]; then
  echo "A valid BACKUP=.sql.gz file is required."
  echo "Run: make backup, then CONFIRM=YES BACKUP=backups/<file>.sql.gz make cutover-zk"
  exit 1
fi

gzip -t "$backup"

echo "Backup verified: $backup"
echo "This operation deletes all users, sessions, and vault entries."
echo "Starting Alembic with the destructive migration gate enabled..."

docker compose run --rm --no-deps -e VAULTLOCAL_ALLOW_DESTRUCTIVE_MIGRATION=1 api alembic upgrade head

echo "ZK cutover completed."
echo "Validate with: docker compose run --rm --no-deps api alembic current"
