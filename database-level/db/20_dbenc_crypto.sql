-- Database-level encryption: pgcrypto inside Postgres. Runs after 10_schema for dbenc.
--
--  * Keys live in dbenc.key_store, readable only by the owner (and any superuser).
--  * Roles never touch ciphertext columns. They call SECURITY DEFINER functions, and the
--    policy "who may decrypt what" is simply GRANT EXECUTE on those functions.
--  * Ciphertext = [1 byte key version] || pgp_sym_encrypt(context || value)
--    where context = '<field>|<employee id>|'. Decryption checks the context, so a ciphertext
--    copied to another employee's row (or another field) is rejected, not silently accepted.
--    (pgcrypto's own integrity check only catches modified bytes, not moved ones.)

SET ROLE dbenc_owner;

CREATE TABLE dbenc.key_store (
  field      text        NOT NULL,
  ver        int         NOT NULL CHECK (ver BETWEEN 1 AND 255),
  key        text        NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (field, ver)
);
REVOKE ALL ON dbenc.key_store FROM PUBLIC;

INSERT INTO dbenc.key_store (field, ver, key)
SELECT f, 1, encode(gen_random_bytes(32), 'hex')
FROM unnest(ARRAY['salary', 'ssn', 'acct', 'dependents']) AS f;

-- ---- internal primitives (no role can execute these directly) ----------------------

CREATE FUNCTION dbenc._enc(p_field text, p_emp int, p_plain text) RETURNS bytea
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v int; k text;
BEGIN
  SELECT ks.ver, ks.key INTO v, k
  FROM dbenc.key_store ks WHERE ks.field = p_field ORDER BY ks.ver DESC LIMIT 1;
  -- s2k-mode=0: our keys are random 256-bit values, not passwords, so iterated key stretching
  -- buys nothing and is ~170x slower (measured: 1000 encrypt+decrypt = 2.07 s vs 0.012 s).
  -- Ciphertext is still randomized (OpenPGP random prefix), so equal plaintexts differ.
  RETURN set_byte('\x00'::bytea, 0, v)
      || pgp_sym_encrypt(p_field || '|' || p_emp || '|' || p_plain, k, 'cipher-algo=aes256, s2k-mode=0');
END $$;

CREATE FUNCTION dbenc._dec(p_field text, p_emp int, p_ct bytea) RETURNS text
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE k text; plain text; ctx text := p_field || '|' || p_emp || '|';
BEGIN
  SELECT ks.key INTO k FROM dbenc.key_store ks
  WHERE ks.field = p_field AND ks.ver = get_byte(p_ct, 0);
  IF k IS NULL THEN
    RAISE EXCEPTION 'no key for % version %', p_field, get_byte(p_ct, 0);
  END IF;
  plain := pgp_sym_decrypt(substring(p_ct FROM 2), k);
  IF left(plain, length(ctx)) <> ctx THEN
    RAISE EXCEPTION 'integrity check failed: % ciphertext does not belong to employee %', p_field, p_emp;
  END IF;
  RETURN substring(plain FROM length(ctx) + 1);
END $$;

-- $20k salary band; must match band() in flc/impl_dbenc.py.
CREATE FUNCTION dbenc.band(p_salary numeric) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
  SELECT '$' || (floor(p_salary / 20000) * 20)::int || 'k-' || (floor(p_salary / 20000) * 20 + 20)::int || 'k'
$$;

-- ---- writers (owner / superuser only): encrypt and derive the masked columns together ----

CREATE FUNCTION dbenc.put_compensation(p_emp int, p_salary numeric, p_freq text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  INSERT INTO dbenc.compensation (emp_id, salary_enc, salary_band, pay_freq)
  VALUES (p_emp, dbenc._enc('salary', p_emp, p_salary::text), dbenc.band(p_salary), p_freq)
  ON CONFLICT (emp_id) DO UPDATE
    SET salary_enc = EXCLUDED.salary_enc, salary_band = EXCLUDED.salary_band, pay_freq = EXCLUDED.pay_freq
$$;

CREATE FUNCTION dbenc.put_tax_bank(p_emp int, p_ssn text, p_bank text, p_acct text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  INSERT INTO dbenc.tax_bank (emp_id, ssn_enc, ssn_last4, bank_name, acct_enc, acct_last4)
  VALUES (p_emp, dbenc._enc('ssn', p_emp, p_ssn), right(p_ssn, 4), p_bank,
          dbenc._enc('acct', p_emp, p_acct), right(p_acct, 4))
  ON CONFLICT (emp_id) DO UPDATE
    SET ssn_enc = EXCLUDED.ssn_enc, ssn_last4 = EXCLUDED.ssn_last4, bank_name = EXCLUDED.bank_name,
        acct_enc = EXCLUDED.acct_enc, acct_last4 = EXCLUDED.acct_last4
$$;

CREATE FUNCTION dbenc.put_benefits(p_emp int, p_plan text, p_tier text, p_dependents text) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  INSERT INTO dbenc.benefits (emp_id, plan_name, coverage_tier, dependents_enc)
  VALUES (p_emp, p_plan, p_tier, dbenc._enc('dependents', p_emp, p_dependents))
  ON CONFLICT (emp_id) DO UPDATE
    SET plan_name = EXCLUDED.plan_name, coverage_tier = EXCLUDED.coverage_tier,
        dependents_enc = EXCLUDED.dependents_enc
$$;

-- ---- scoped decryption paths (the only way a role gets plaintext) -------------------

CREATE FUNCTION dbenc.salary_of(p_emp int) RETURNS numeric
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT dbenc._dec('salary', c.emp_id, c.salary_enc)::numeric FROM dbenc.compensation c WHERE c.emp_id = p_emp
$$;

CREATE FUNCTION dbenc.ssn_of(p_emp int) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT dbenc._dec('ssn', t.emp_id, t.ssn_enc) FROM dbenc.tax_bank t WHERE t.emp_id = p_emp
$$;

CREATE FUNCTION dbenc.acct_of(p_emp int) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT dbenc._dec('acct', t.emp_id, t.acct_enc) FROM dbenc.tax_bank t WHERE t.emp_id = p_emp
$$;

CREATE FUNCTION dbenc.dependents_of(p_emp int) RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT dbenc._dec('dependents', b.emp_id, b.dependents_enc) FROM dbenc.benefits b WHERE b.emp_id = p_emp
$$;

-- Employee self-service: no id parameter, so only the viewer's own row can ever be decrypted.
CREATE FUNCTION dbenc.my_salary() RETURNS numeric
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT dbenc._dec('salary', c.emp_id, c.salary_enc)::numeric FROM dbenc.compensation c WHERE c.emp_id = dbenc.me()
$$;

CREATE FUNCTION dbenc.my_dependents() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT dbenc._dec('dependents', b.emp_id, b.dependents_enc) FROM dbenc.benefits b WHERE b.emp_id = dbenc.me()
$$;

-- Payroll processing: gross pay per period + the account to pay into, decrypted server-side.
CREATE FUNCTION dbenc.payroll_run(p_periods int DEFAULT 26)
RETURNS TABLE (emp_id int, full_name text, gross_per_period numeric, bank_name text, acct_number text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT e.emp_id, e.full_name,
         round(dbenc._dec('salary', c.emp_id, c.salary_enc)::numeric / p_periods, 2),
         t.bank_name, dbenc._dec('acct', t.emp_id, t.acct_enc)
  FROM dbenc.employees e
  JOIN dbenc.compensation c USING (emp_id)
  JOIN dbenc.tax_bank t USING (emp_id)
  ORDER BY e.emp_id
$$;

-- ---- key rotation: new key version, then re-encrypt every row of that field inside the DB ----

CREATE FUNCTION dbenc.rotate_key(p_field text) RETURNS int
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE newv int;
BEGIN
  SELECT coalesce(max(ver), 0) + 1 INTO newv FROM dbenc.key_store WHERE field = p_field;
  INSERT INTO dbenc.key_store (field, ver, key) VALUES (p_field, newv, encode(gen_random_bytes(32), 'hex'));
  IF    p_field = 'salary'     THEN UPDATE dbenc.compensation SET salary_enc = dbenc._enc('salary', emp_id, dbenc._dec('salary', emp_id, salary_enc));
  ELSIF p_field = 'ssn'        THEN UPDATE dbenc.tax_bank     SET ssn_enc    = dbenc._enc('ssn', emp_id, dbenc._dec('ssn', emp_id, ssn_enc));
  ELSIF p_field = 'acct'       THEN UPDATE dbenc.tax_bank     SET acct_enc   = dbenc._enc('acct', emp_id, dbenc._dec('acct', emp_id, acct_enc));
  ELSIF p_field = 'dependents' THEN UPDATE dbenc.benefits     SET dependents_enc = dbenc._enc('dependents', emp_id, dbenc._dec('dependents', emp_id, dependents_enc));
  ELSE RAISE EXCEPTION 'unknown field %', p_field;
  END IF;
  RETURN newv;
END $$;

-- ---- who may decrypt what ------------------------------------------------------------
GRANT EXECUTE ON FUNCTION dbenc.salary_of(int)     TO r_payroll, r_hr;
GRANT EXECUTE ON FUNCTION dbenc.ssn_of(int)        TO r_payroll;
GRANT EXECUTE ON FUNCTION dbenc.acct_of(int)       TO r_payroll;
GRANT EXECUTE ON FUNCTION dbenc.dependents_of(int) TO r_hr;
GRANT EXECUTE ON FUNCTION dbenc.my_salary()        TO r_employee;
GRANT EXECUTE ON FUNCTION dbenc.my_dependents()    TO r_employee;
GRANT EXECUTE ON FUNCTION dbenc.payroll_run(int)   TO r_payroll;
-- No role has any grant on the *_enc columns or on dbenc.key_store.

-- ---- sign-in ---------------------------------------------------------------------------
-- Passwords are hashed, not encrypted: bcrypt (crypt + gen_salt('bf')) is one-way, so even the key hunt
-- cannot turn a stored value back into a password. Only the superuser calls put_user (no grant).

CREATE FUNCTION dbenc.put_user(p_username text, p_password text, p_role text, p_emp int) RETURNS void
LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  INSERT INTO dbenc.app_users (username, pw_hash, role, emp_id)
  VALUES (lower(p_username), crypt(p_password, gen_salt('bf', 10)), p_role, p_emp)
  ON CONFLICT (username) DO UPDATE SET pw_hash = excluded.pw_hash, role = excluded.role, emp_id = excluded.emp_id
$$;

-- Returns one row (database role, employee id, name, title) for a correct username + password, otherwise nothing.
-- An unknown username still pays for one bcrypt, so the response time does not reveal which usernames exist.
CREATE FUNCTION dbenc.authenticate(p_username text, p_password text)
RETURNS TABLE (role text, emp_id int, full_name text, title text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE u dbenc.app_users;
BEGIN
  SELECT * INTO u FROM dbenc.app_users a WHERE a.username = lower(p_username);
  IF NOT FOUND THEN
    PERFORM crypt(p_password, gen_salt('bf', 10));
    RETURN;
  END IF;
  IF u.pw_hash <> crypt(p_password, u.pw_hash) THEN
    RETURN;
  END IF;
  RETURN QUERY SELECT u.role, u.emp_id, e.full_name, e.title
               FROM (SELECT 1) AS one LEFT JOIN dbenc.employees e ON e.emp_id = u.emp_id;
END $$;
GRANT EXECUTE ON FUNCTION dbenc.authenticate(text, text) TO r_auth;

-- ---- employee directory lookup ------------------------------------------------------------
-- An employee may search for a colleague by name or ID but gets back only the ID and the name: nothing else about
-- them (department, title, email, pay, bank, benefits). The employees table itself stays limited to the viewer's own row.
CREATE FUNCTION dbenc.directory(p_q text, p_limit int DEFAULT 25)
RETURNS TABLE (emp_id int, full_name text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT e.emp_id, e.full_name FROM dbenc.employees e
  WHERE CASE WHEN p_q ~ '^[0-9]{1,9}$' THEN e.emp_id = p_q::int
             ELSE e.full_name ILIKE '%' || replace(replace(replace(p_q, '\', '\\'), '%', '\%'), '_', '\_') || '%' END
  ORDER BY e.full_name, e.emp_id LIMIT least(p_limit, 25)
$$;
GRANT EXECUTE ON FUNCTION dbenc.directory(text, int) TO r_employee;
GRANT USAGE ON SCHEMA dbenc TO r_auth;

RESET ROLE;
