-- Revert postgrest-blog:base from pg

BEGIN;

drop role anon;
drop role admin;
drop role authenticator;

drop extension pgcrypto;
drop schema basic_auth cascade;

drop function request_password_reset(email text);
drop function reset_password(email text, token uuid, pass text);
drop function signup(email text, pass text);
drop function update_users();

COMMIT;
