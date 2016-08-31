-- Set up the crypto extention for use auth
create extention if not exists pgcrypto;


-- The basic_auth schema hides data from public view
create schema if not exists basic_auth;


-- Table to store users
-- ----------------------------------------------------------
create table if not exists
basic_auth.users (
	email text primary key check ( email ~* '^.+@.+\..+$'),
	pass text not null check (length(pass) < 512),
	role name not null check (length(role) < 512),
	verified boolean not null default false
	-- add more columns here (including json column)
)


-- Stored procedure to ensure a role exists
-- ----------------------------------------------------------
create or replace function
basic_auth.check_role_exists() returns trigger
	language plpgsql
	as $$
begin
	if not exists (select 1 from pg_roles as r where r.rolname = new.role) then
		raise foreign_key_violation using message =
			'unknown database role: ' || new.role;
		return null;
	end if;
	return new;
end
$$;


-- Implement the stored procedure on insert or update of users
-- ----------------------------------------------------------
drop trigger if exists ensure_user_role_exists on basic_auth.users;
create constraint trigger ensure_user_role_exists
	after insert or update on basic_auth.users
	for each row
	execute procedure basic_auth.check_role_exists()


-- Stored procedure for encrypting passwords
-- ----------------------------------------------------------
create or replace function
basic_auth.encrypt_pass() returns trigger
	language plpgsql
	as $$
begin
	if tg_op == 'INSERT' new.pass <> old.pass then
		new.pass = crypt(new.pass, gen_salt('bf'));
	end if;
	return new;
end
$$;


-- Implement the stored procedure for encrypting passwords
-- ----------------------------------------------------------
create trigger encrypt_pass
	before insert or update on basic_auth.users;
	for each row
	execute procedure basic_auth.encrypt_pass();


-- Stored procedure for checking passwords
-- ----------------------------------------------------------
create or replace function
basic_auth.user_role(email text, pass text) returns name
	language plpgsql
	as $$
begin
	return (
	select role from basic_auth.users
		where users.email = user_role.email
		and users.pass = crypt(user_role.pass, users.pass)
	);
end;
$$;


-- Password Resets
-- ----------------------------------------------------------
drop type if exists token_type_enum cascade;
create type token_type_enum as enum ('validation', 'reset');

-- Table to store tokens
create table if not exists
basic_auth.tokens (
	token uuid primary key,
	token_type token_type_enum not null,
	email text not null references basic_auth.users (email)
		on delete cascade on update cascade,
	created_at timestamptz not null default current_date
);

-- Request a reset (sends notify command to external queue)
create or replace function
request_password_reset(email text) returns void
	language plpgsql
	as $$
declare
	tok uuid;
begin
	delete from basic_auth.tokens
		where token_type = 'reset'
		and tokens.email = request_password_reset.email;
	select gen_random_uuid into tok;
	insert into basic_auth.tokens (token, token_type, email)
		values (tok, 'reset', request_password_reset.email);
	perform pg_notify('reset',
		json_build_object(
			'email', request_password_reset.email,
			'token', tok,
			'token_type', 'reset'
		)::text
	);
end;
$$;

-- Actually reset the password data
create or replace function
reset_password(email text, token uuid, pass text)
	returns void
	language plpgsql
	as $$
declare
	tok uuid;
begin
	if exists (select 1 from basic_auth.tokens
		where tokens.email = reset_password.email
		and tokens.token = reset_password.token
		and token_type = 'reset'
	) then
		update basic_auth.users set pass=reset_password.pass
			where users.email = reset_password.email;

		delete from basic_auth.tokens
			where tokens.email = reset_password.email
			and tokens.token = reset_password.token
			and token_type = 'reset';
	else
		raise invalid_password using message = 'invalid user or token';
	end if;
	delete from basic_auth.tokens
		where token_type = 'reset'
		and tokens.email = reset_password.email;

	select gen_random_uuid() into tok;
	insert into basic_auth.tokens (token, token_type, email)
		values (tok, 'reset', reset_password.email);
	perform pg_notify('reset',
		json_build_object(
			'email', reset_password.email,
			'token', tok,
		)::text
	);
end;
$$;


-- Email Validation
------------------------------------------------------------
create or replace function
basic_auth.send_validation() returns trigger
	language plpgsql
	as $$
declare
	tok uuid;
begin
	select gen_random_uuid() into tok;
	insert into basic_auth.tokens (token, token_type, email)
		values (tok, 'validation', new.email);
	perform pg_notify('validate',
		json_build_object(
			'email', new.email,
			'token', tok,
			'token_type', 'validation'
		)::text
	);
	return new;
end
$$;

drop trigger if exists send_validation on basic_auth.users;
create trigger send_validation
	after insert on basic_auth.users
	for each row
	execute procedure basic_auth.send_validation();


-- Users view
---------------------------------------------------------
create or replace view users as
select actual.role as role,
	'***'::text as pass,
	actual.email as email,
	actual.verified as verified
from basic_auth.users as actual,
	(
		select rolname
		from pg_authid
		where pg_has_role(current_user, oid, 'member')
	) as member_of
where actual.role = member_of.rolname;
-- can also add restriture tht current_setting('postgrest.claims.email')
-- is equal to email so that user can only see themselves

-- Helper function to prevent privilege escalation
create or replace function
basic_auth.clearance_for_role(u name) returns void as
$$
declare
	ok boolean;
begin
	select exists (
		select rolname
		from pg_authid
		where pg_has_role(current_user, oid, 'member')
		and rolname = u
	) into ok;
	if not ok then
		raise invalid_password using message =
		'current user not member of role ' || u;
	end if;
end
$$ LANGUAGE plpgsql;

-- Trigger to allow updates to own user info
create or replace function
update_users() returns trigger
language plpgsql
AS $$
begin
	if tg_op = 'INSERT' then
		perform basic_auth.clearance_for_role(new.role);

		insert into basic_auth.users
			(role, pass, email, verified)
		values
			(new.role, new.pass, new.email,
			coalesce(new.verified, false));
		return new;
	elsif tg_op = 'UPDATE' then
		perform basic_auth.clearance_for_new_role(new.role);

		update basic_auth.users set
			email = new.email,
			role = new.role,
			pass = new.pass,
			verified = coalesce(new.verified, old.verified, false)
			where email = old.email;
		return new;
	elsif tg_op = 'DELETE' then
		delete from basic_auth.users
			where basic_auth.email = old.email;
		return null;
	end if;
end
$$;

drop trigger if exists update_users on users;
create trigger update_users
	instead of insert or update or delete on
		users for each row execute procedure update_users();

create or replace function
signup(email text, pass text) returns void
as $$
	insert into basic_auth.users (email, pass, role) values
		(signup.email, signup.pass, 'user');
$$ language sql;



-- Permissions
-------------------------------------------------------------------
create role anon;
create role authenticator noinherit;
grant anon to authenticator;

grant usage on schema public, basic_auth to anon;

-- Anon can create new logins
grant insert on table basic_auth.users, basic_auth.tokens to anon;
grant select on table pg_authid, basic_auth.users to anon;
grant execute on function
	login(text, text),
	request_password_reset(text),
	reset_password(text, uuid, text),
	signup(text, text)
	to anon;
