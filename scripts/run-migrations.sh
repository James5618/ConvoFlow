#!/usr/bin/env bash
set -euo pipefail

# Simple PostgreSQL migration runner
# Usage: ./scripts/run-migrations.sh -d <database-url> OR set DATABASE_URL env var

DB_URL="${DATABASE_URL:-}" 
if [ -z "$DB_URL" ]; then
  echo "DATABASE_URL is not set. Provide via env or set DATABASE_URL in environment." >&2
  echo "Example: DATABASE_URL=postgresql://user:pass@localhost:5432/convoflow ./scripts/run-migrations.sh" >&2
  exit 1
fi

MIGRATIONS_DIR="$(dirname "$0")/migrations"

if [ ! -d "$MIGRATIONS_DIR" ]; then
  echo "Migrations directory not found: $MIGRATIONS_DIR" >&2
  exit 1
fi

echo "Running migrations from $MIGRATIONS_DIR against $DB_URL"

for sql in $(ls "$MIGRATIONS_DIR"/*.sql | sort); do
  echo "Applying migration: $sql"
  psql "$DB_URL" -f "$sql"
done

echo "Migrations completed"
