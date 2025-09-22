# Migrations

This project includes simple SQL migrations under `scripts/migrations/`.

Quick guide

- Ensure you have `psql` (Postgres client) available and your Postgres server running.
- Set `DATABASE_URL` to point to your database. Example:

```
export DATABASE_URL=postgresql://convoflow:password@localhost:5432/convoflow
```

- Run the migration runner:

```
./scripts/run-migrations.sh
```

What this does

- Applies `.sql` files in `scripts/migrations/` in lexicographic order.
- The repository currently adds:
  - `20250922_add_voice_and_role.sql` — adds `rooms.is_voice` and `server_members.role`.

Notes

- These migrations are intentionally simple; for production you should use a proper migration tool (Flyway, Liquibase, Knex, or Sequelize migrations, etc.) and include transactional checks and version tracking.
