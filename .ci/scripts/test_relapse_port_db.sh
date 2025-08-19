#!/usr/bin/env bash
#
# Test script for 'relapse_port_db'.
#   - configures relapse and a postgres server.
#   - runs the port script on a prepopulated test sqlite db. Checks that the
#     return code is zero.
#   - reruns the port script on the same sqlite db, targetting the same postgres db.
#     Checks that the return code is zero.
#   - runs the port script against a new sqlite db. Checks the return code is zero.
#
# Expects Relapse to have been already installed with `poetry install --extras postgres`.
# Expects `poetry` to be available on the `PATH`.

set -xe -o pipefail
cd "$(dirname "$0")/../.."

echo "--- Generate the signing key"
poetry run relapse_homeserver --generate-keys -c .ci/sqlite-config.yaml

echo "--- Prepare test database"
# Make sure the SQLite3 database is using the latest schema and has no pending background updates.
poetry run update_relapse_database --database-config .ci/sqlite-config.yaml --run-background-updates

# Create the PostgreSQL database.
psql -c "CREATE DATABASE relapse"

echo "+++ Run relapse_port_db against test database"
# TODO: this invocation of relapse_port_db (and others below) used to be prepended with `coverage run`,
# but coverage seems unable to find the entrypoints installed by `pip install -e .`.
poetry run relapse_port_db --sqlite-database .ci/test_db.db --postgres-config .ci/postgres-config.yaml

# We should be able to run twice against the same database.
echo "+++ Run relapse_port_db a second time"
poetry run relapse_port_db --sqlite-database .ci/test_db.db --postgres-config .ci/postgres-config.yaml

#####

# Now do the same again, on an empty database.

echo "--- Prepare empty SQLite database"

# we do this by deleting the sqlite db, and then doing the same again.
rm .ci/test_db.db

poetry run update_relapse_database --database-config .ci/sqlite-config.yaml --run-background-updates

# re-create the PostgreSQL database.
psql \
  -c "DROP DATABASE relapse" \
  -c "CREATE DATABASE relapse"

echo "+++ Run relapse_port_db against empty database"
poetry run relapse_port_db --sqlite-database .ci/test_db.db --postgres-config .ci/postgres-config.yaml

echo "--- Create a brand new postgres database from schema"
cp .ci/postgres-config.yaml .ci/postgres-config-unported.yaml
sed -i -e 's/database: relapse/database: relapse_unported/' .ci/postgres-config-unported.yaml
psql -c "CREATE DATABASE relapse_unported"
poetry run update_relapse_database --database-config .ci/postgres-config-unported.yaml --run-background-updates

echo "+++ Comparing ported schema with unported schema"
# Ignore the tables that portdb creates. (Should it tidy them up when the porting is completed?)
psql relapse -c "DROP TABLE port_from_sqlite3;"
pg_dump --format=plain --schema-only --no-tablespaces --no-acl --no-owner --restrict-key=abcd relapse_unported > unported.sql
pg_dump --format=plain --schema-only --no-tablespaces --no-acl --no-owner --restrict-key=abcd relapse          >   ported.sql
# By default, `diff` returns zero if there are no changes and nonzero otherwise
diff -u unported.sql ported.sql | tee schema_diff