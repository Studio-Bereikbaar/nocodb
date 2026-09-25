-- Least-privilege role for sso-bridge in the NocoDB meta DB. Run once as the meta DB owner, with
-- psql -v pw=<password from bws NC_SSO_BRIDGE_DB_PASSWORD>. Idempotent.
-- The bridge can read who a user is and add refresh tokens; it cannot read password hashes,
-- change users or roles, or touch any other NocoDB table.
SELECT format('CREATE ROLE nc_sso_bridge LOGIN PASSWORD %L', :'pw')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nc_sso_bridge') \gexec
ALTER ROLE nc_sso_bridge PASSWORD :'pw';
ALTER ROLE nc_sso_bridge CONNECTION LIMIT 5;
SELECT format('GRANT CONNECT ON DATABASE %I TO nc_sso_bridge', current_database()) \gexec
GRANT USAGE ON SCHEMA public TO nc_sso_bridge;
GRANT SELECT (id, email, token_version, blocked, deleted_at) ON public.nc_users_v2 TO nc_sso_bridge;
GRANT SELECT (fk_user_id, token, expires_at), INSERT (fk_user_id, token, meta, expires_at, created_at, updated_at)
   ON public.nc_user_refresh_tokens TO nc_sso_bridge;
