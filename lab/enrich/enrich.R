# lab/enrich/enrich.R
#
# Enrichment layer: attach coarse, non-identifying context to events and build the
# semantic anchor table used by the feature layer.
#
# Fixes relative to the design notes this file came from:
#
# 1. Every query is parameterized with DBI::dbBind. The original snippet assembled
#    SQL with paste0() around values that come from attacker-controlled text
#    (user agents, forum posts). That is textbook second-order SQL injection and it
#    is the reason the analysis role in 001_schema.sql has no DDL rights.
# 2. Input is length-capped and control characters are stripped before it reaches
#    the database, so a single event cannot carry a 5 MB payload into a text column.
# 3. The script is idempotent: it works on a bounded batch and records progress,
#    so a crash mid-run does not double-apply enrichment.
# 4. Nothing here calls out to a geolocation or reputation API. Enrichment is
#    derived from data already in the database, which keeps the lab offline.
#
# Status: parsed and exercised against a real PostgreSQL 18.6 instance (R 4.6.2,
# DBI 1.3.0, RPostgres 1.4.10). The sanitiser, the cursor paging, and the
# ON CONFLICT idempotency are covered by lab/tests/test_enrich_r.py, which skips
# when R is absent rather than pretending to pass. See lab/README.md for how the
# sandbox was provisioned.

suppressPackageStartupMessages({
  library(DBI)
  library(RPostgres)
})

MAX_TEXT_CHARS <- 512L
BATCH_SIZE <- 5000L

sanitize_text <- function(x) {
  if (is.na(x)) {
    return("")
  }
  # Drop control and format characters, collapse whitespace, then cap the length.
  #
  # The first version of this line was written as a literal range from \u0000 to
  # \u001f, which does not parse: R forbids a nul character in a string literal, so
  # the whole file failed at parse time and never reached a database. R strings
  # cannot contain a nul at all, so the range was never expressible this way.
  # \p{Cc} covers C0 and C1 controls; \p{Cf} covers the zero-width and bidi
  # characters, which are the ones worth worrying about in a log field.
  x <- gsub("[\\p{Cc}\\p{Cf}]", " ", x, perl = TRUE)
  x <- gsub("[[:space:]]+", " ", x)
  x <- trimws(x)
  if (nchar(x) > MAX_TEXT_CHARS) {
    x <- substr(x, 1L, MAX_TEXT_CHARS)
  }
  x
}

connect <- function() {
  # Credentials come from the environment, never from the script.
  dbConnect(
    RPostgres::Postgres(),
    host = Sys.getenv("PGHOST", "localhost"),
    port = as.integer(Sys.getenv("PGPORT", "5432")),
    dbname = Sys.getenv("PGDATABASE", "lab"),
    user = Sys.getenv("PGUSER", "lab_analysis"),
    password = Sys.getenv("PGPASSWORD", ""),
    sslmode = Sys.getenv("PGSSLMODE", "prefer")
  )
}

enrich_batch <- function(con, since_event_id = NULL, limit = BATCH_SIZE) {
  # Parameterized: $1 and $2 are bound values, never interpolated text.
  #
  # Ordered by event_id, not observed_at, because event_id is the cursor. Paging by
  # one column and ordering by another revisits rows and skips others as soon as
  # the two disagree, which is silent on a small dataset and wrong on a large one.
  rows <- dbGetQuery(
    con,
    "SELECT event_id, observed_at, client_key, channel, ua_family, protocol, latency_ms
       FROM events
      WHERE ($1::uuid IS NULL OR event_id > $1::uuid)
      ORDER BY event_id
      LIMIT $2",
    # A bare NULL in `params` is rejected by RPostgres ("Parameter does not have
    # length 0"), so the first page sends a typed NA and lets the server see NULL.
    params = list(if (is.null(since_event_id)) NA_character_ else since_event_id, limit)
  )
  if (nrow(rows) == 0) {
    return(list(rows = 0L, inserted = 0L, cursor = since_event_id))
  }

  # Coarse derived columns only: no address, no raw agent string.
  rows$pace_bucket <- ifelse(rows$latency_ms < 50, "fast",
                      ifelse(rows$latency_ms < 200, "normal", "slow"))

  inserted <- 0L
  dbWithTransaction(con, {
    for (i in seq_len(nrow(rows))) {
      # dbExecute returns the affected count, which is 0 for a conflicting row. Counting
      # rows read instead would report work that did not happen: the loop below would
      # print "enriched 7 rows" on a second pass that inserted nothing.
      inserted <- inserted + dbExecute(
        con,
        "INSERT INTO enrichment (event_id, pace_bucket, enriched_at)
         VALUES ($1::uuid, $2, now())
         ON CONFLICT (event_id) DO NOTHING",
        params = list(rows$event_id[i], rows$pace_bucket[i])
      )
    }
  })
  list(rows = nrow(rows), inserted = inserted, cursor = rows$event_id[[nrow(rows)]])
}

# Semantic anchors: instead of building SQL from candidate strings, ask the
# database for similarity against the parameterized anchor. pg_trgm does the work.
find_similar_anchors <- function(con, candidate_text, threshold = 0.4, max_rows = 20L) {
  dbGetQuery(
    con,
    "SELECT anchor_id, anchor_text, similarity(anchor_text, $1) AS score
       FROM semantic_anchors
      WHERE similarity(anchor_text, $1) >= $2
      ORDER BY score DESC
      LIMIT $3",
    params = list(sanitize_text(candidate_text), threshold, max_rows)
  )
}

main <- function() {
  con <- connect()
  on.exit(dbDisconnect(con), add = TRUE)
  total <- 0L
  cursor <- NULL
  repeat {
    # The cursor has to advance. The first version called enrich_batch(con) with no
    # cursor, so every pass re-read the same first batch, inserted nothing new
    # because of ON CONFLICT, counted the same rows again, and never terminated.
    # A loop that cannot terminate is worse than an error: it looks like work.
    batch <- enrich_batch(con, since_event_id = cursor)
    total <- total + batch$inserted
    if (batch$rows == 0L || identical(batch$cursor, cursor)) {
      break
    }
    cursor <- batch$cursor
    message(sprintf("read %d rows, inserted %d (running total %d)", batch$rows, batch$inserted, total))
  }
  invisible(total)
}

if (sys.nframe() == 0L) {
  main()
}
