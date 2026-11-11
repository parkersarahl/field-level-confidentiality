#!/usr/bin/env bash
# Backup / proof beat: Postgres itself enforces the policy. No app involved.
#   PGHOST=localhost PGPORT=5432 ./demo/psql_demo.sh        (FLC_ADMIN_PASSWORD for the superuser if needed)
set -u
DB="${FLC_DB:-flc}"

run() {  # run <role> <sql>
  local role="$1" sql="$2" pw
  if [ "$role" = "postgres" ]; then pw="${FLC_ADMIN_PASSWORD:-}"; else pw="${FLC_ROLE_PASSWORD:-demo}"; fi
  echo; echo "[$role]> $sql"
  PGPASSWORD="$pw" psql -X -q -d "$DB" -U "$role" -c "$sql" 2>&1 | sed 's/^/    /'
}

echo "=== pgcrypto inside Postgres ==================================================="
run r_analyst "select * from dbenc.tax_bank limit 1"
run r_analyst "select dbenc.ssn_of(1)"
run r_hr      "select dbenc.ssn_of(1)"
run r_payroll "select dbenc.ssn_of(1)"
run r_payroll "select emp_id, ssn_last4, acct_last4 from dbenc.tax_bank where emp_id = 1"

echo; echo "=== The curious DBA ============================================================"
run postgres  "select emp_id, left(encode(ssn_enc, 'hex'), 40) || '...' as ssn_enc, ssn_last4 from dbenc.tax_bank where emp_id = 1"
run postgres  "select field, ver, left(key, 12) || '...' as key from dbenc.key_store"
run postgres  "select split_part(pgp_sym_decrypt(substring(ssn_enc from 2), (select key from dbenc.key_store where field = 'ssn' and ver = get_byte(ssn_enc, 0))), '|', 3) as ssn from dbenc.tax_bank where emp_id = 1"
