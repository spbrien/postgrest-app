-- Revert postgrest-blog:appschema from pg

BEGIN;

-- XXX Add DDLs here.

DROP SCHEMA blog;

COMMIT;
