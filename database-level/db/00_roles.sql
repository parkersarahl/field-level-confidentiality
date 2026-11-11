-- Cluster-wide roles. Run once as a superuser (init_db does this).
--
-- r_auth is the pre-login connection: it can run dbenc.authenticate() and nothing else.
-- Each application role is its own LOGIN role, so a compromised connection cannot
-- SET ROLE its way into a more privileged role. (In production each would get its
-- own credential and connection pool.)

DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['r_employee', 'r_payroll', 'r_hr', 'r_analyst', 'r_auth'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('CREATE ROLE %I LOGIN PASSWORD %L', r, 'demo');
    END IF;
  END LOOP;

  -- The schema owner: owns the tables and the SECURITY DEFINER functions. Nobody logs in as it.
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dbenc_owner') THEN
    CREATE ROLE dbenc_owner NOLOGIN;
  END IF;
END $$;

-- Functions are executable by nobody unless granted explicitly.
ALTER DEFAULT PRIVILEGES FOR ROLE dbenc_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

CREATE EXTENSION IF NOT EXISTS pgcrypto SCHEMA public;
