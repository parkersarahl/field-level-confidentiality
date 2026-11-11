#!/usr/bin/env bash
# Demonstration: rebuild the database, then run the raw psql proof (no application involved).
set -euo pipefail
cd "$(dirname "$0")/.."
python -m flc.init_db --employees "${FLC_EMPLOYEES:-1000}"
./demo/psql_demo.sh
echo
echo "Next: flask --app app run   then open  /compare/1   /dba/1   /report"
echo "      SQL scripts for DBeaver are in sql_tests/"
