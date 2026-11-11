#!/usr/bin/env bash
# Rebuild the database and run the pytest suite, saving the output to results/pytest.txt.
# Needs the usual settings: PGHOST, FLC_ADMIN_PASSWORD (and PGPORT if not 5432).
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p results
python -m flc.init_db --employees "${FLC_EMPLOYEES:-1000}"
set +e
python -m pytest 2>&1 | tee results/pytest.txt
status=${PIPESTATUS[0]}
echo; echo "Saved: results/pytest.txt"
exit $status
