-- Verify postgrest-blog:appschema on pg

BEGIN;

-- XXX Add verifications here.

SELECT pg_catalog.has_schema_privilege('blog', 'usage');

ROLLBACK;
