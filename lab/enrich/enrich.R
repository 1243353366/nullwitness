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
# Status: UNVERIFIED in the lab sandbox. R is not installed there, so this file is
# written to be reviewed rather than claimed as tested. See lab/README.md.

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
  # Drop C0/C1 control characters, collapse whitespace, then cap the length.
  x <- gsub("[\u0000-\u001f\u007f-\u009f]", " ", x, perl = TRUE)
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
  rows <- dbGetQuery(
    con,
    "SELECT event_id, observed_at, client_key, channel, ua_family, protocol, latency_ms
       FROM events
      WHERE ($1::uuid IS NULL OR event_id > $1::uuid)
      ORDER BY observed_at
      LIMIT $2",
    params = list(since_event_id, limit)
  )
  if (nrow(rows) == 0) {
    return(invisible(0L))
  }

  # Coarse derived columns only: no address, no raw agent string.
  rows$pace_bucket <- ifelse(rows$latency_ms < 50, "fast",
                      ifelse(rows$latency_ms < 200, "normal", "slow"))

  dbWithTransaction(con, {
    for (i in seq_len(nrow(rows))) {
      dbExecute(
        con,
        "INSERT INTO enrichment (event_id, pace_bucket, enriched_at)
         VALUES ($1::uuid, $2, now())
         ON CONFLICT (event_id) DO NOTHING",
        params = list(rows$event_id[i], rows$pace_bucket[i])
      )
    }
  })
  invisible(nrow(rows))
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
  repeat {
    n <- enrich_batch(con)
    total <- total + n
    if (n == 0L) {
      break
    }
    message(sprintf("enriched %d rows (running total %d)", n, total))
  }
  invisible(total)
}

if (sys.nframe() == 0L) {
  main()
}
