#!/bin/sh
# 002_pilot_roles.sh - let the least-privilege roles log in, if passwords were supplied.
#
# 001_schema.sql creates lab_analysis and lab_ingest NOLOGIN, which is correct: they are
# database roles for programs, and a role that cannot log in cannot be used to log in by
# someone who finds its name. But the pilot's own documentation then told an operator to
# connect as lab_analysis, and no password could ever have worked. Rather than weaken the
# schema for everybody, the pilot gets a bootstrap step that is explicitly opt-in: set
# ANALYSIS_PASSWORD (and optionally INGEST_PASSWORD) in lab/.env, and this grants LOGIN with
# exactly that password. Leave them blank and the roles stay NOLOGIN.
#
# Values reach psql as variables and are quoted there (:"role" as an identifier, :'pw' as a
# literal), so an operator's punctuation cannot become SQL. That only works for statements
# psql reads from standard input: `psql -c` does not interpolate variables at all. The first
# version of this file used -c, which made it fail on a bare colon rather than grant anything.
# The statements below go on stdin for that reason, and a test runs them against a live
# server with a password containing a quote.
#
# The entrypoint runs this file from /docker-entrypoint-initdb.d after 001_schema.sql, on
# first init only. An existing volume keeps whatever the roles already were.

set -eu

psql_() {
    psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" "$@"
}

grant_login() {
    role="$1"
    password="$2"
    if [ -z "$password" ]; then
        echo "002_pilot_roles: no password for $role, leaving it NOLOGIN"
        return 0
    fi
    psql_ -v role="$role" -v pw="$password" <<'SQL'
ALTER ROLE :"role" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD :'pw';
SQL
    echo "002_pilot_roles: $role can now log in with the password from the environment"
}

grant_login lab_analysis "${ANALYSIS_PASSWORD:-}"
grant_login lab_ingest "${INGEST_PASSWORD:-}"
