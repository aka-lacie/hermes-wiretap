# Error accounting: backend contract and coverage

This first backend increment broadens error visibility beyond HTTP 429 without
changing capture, migrating a store, or changing the Inspector frontend.

## Available now

Dashboard `/calls` rows and CLI call-list rows include an additive
`error_summary` object:

```json
{"v":1,"scope":"call","outcome":"succeeded","category":null,"affected":true,"recovered":true,"recorded_failure_observations":1}
```

- `outcome`: `succeeded` for stored HTTP 2xx unless an explicit `response_error`
  establishes an invalid empty response; `failed` for that semantic failure or
  an explicit other status (including the collector's `0` non-HTTP failure sentinel);
  `unknown` for a missing status. Unknown can mean in flight, interrupted, or uncaptured.
- `category`: `invalid_response` for the explicit empty-response signal; otherwise
  coarse final-status classification: `authentication` (401),
  `permission` (403), `rate_limit` (429), `server` (5xx), `http` (other explicit
  statuses), or `transport_or_invalid_response` (0). A 429 is still preserved
  separately as `n429`. HTTP 499 is reported as HTTP evidence; it does not prove
  a provider fault, since proxies may use it for client cancellation.
- `affected`: explicit failed outcome or positive stored `nfail`.
- `recovered`: stored 2xx outcome after positive stored `nfail`. This can mean
  recovery via retry/rotation/fallback; it does not establish which mechanism.
- `recorded_failure_observations`: existing `nfail`, unchanged, including null
  when unavailable. It is NOT a globally deduplicated physical-attempt count.

Family summaries add `failed_calls`, `affected_calls`, `recovered_calls`,
`unknown_calls`, and `recorded_failure_observations`. Existing `err` remains an
alias for failed calls and now includes explicit status-0 failures instead of
silently dropping them. Existing `n429` remains untouched. These counters use
stored calls as their unit, not conversation turns. An aggregate zero means
no recorded evidence in that window, not proof that nothing failed.

`--errors` / `errors=1` includes explicit failed outcomes and recorded failed
observations, including recovered calls. It excludes bare unknown/pending
rows. It accepts all HTTP 2xx as successful, rather than only 200.

No raw provider messages, response bodies, headers, credential values or error
strings are added to this API surface. Provider/model and optional safe
credential-label fields stay on their existing paths. Old stores are read as
before; no backfill is performed. This does not update model/key aggregate
cards yet: their existing fields remain stable for the frontend owner.

## Follow-up: source-aware observations, not inflated totals

The current collector already receives general `api_request_error` callbacks:
HTTP failures, SDK transport exceptions, invalid responses and truncation paths.
It stores bounded host `attempt_detail` plus `nfail`. Proxy enrichment now keeps
its upstream sequence separately in `proxy_attempts`, with file/attempt identities;
it no longer overwrites host attempt details. `calls.host_state` stores host-local
totals independently of optional/bounded payload details; both writers project legacy
aggregate counters from maxima of the two source-local totals. Callback/poller
ordering therefore cannot add the same observation at both layers. Both writer
paths reserve the SQLite writer before source-state reads, so a separate connection
cannot commit between the snapshot and its projected update. The caller retains
transaction commit/rollback ownership. This is still not a globally deduplicated
physical-attempt count. Already merged legacy rows
without source-local state can seed it only from identifiable retained host evidence.
Per-attempt upstream requests and responses survive in wire storage until normal
retention expiry, including across host retries. Cross-family detach explicitly
marks these observations detached, rather than making them the final response.

`response_error='empty_response'` is a narrow additional final-outcome signal:
a completed downstream HTTP200, empty captured body, and zero output/reasoning
usage. The HTTP status remains200. This is a failed `invalid_response`, never a
recovered success merely because its status is2xx. Error filters, error ordering,
family and credential call summaries share that interpretation. Missing bodies
and zero usage alone do not establish this signal. A successful host retry clears
the terminal signal while retaining the earlier failure observation.

A fuller generalized error design should retain separate observations with stable provenance:

- call ID and observation ID; turn ID when the host supplies it;
- layer (`hermes`, `proxy_upstream`, `provider_response`), retry/physical attempt
  identity when actually known, timestamp and evidence source;
- HTTP status independently from semantic error kind/code; retryable when
  supplied, not guessed; recovery mechanism only when directly observed;
- provider/requested+served model and optional non-secret credential label;
- bounded sanitized code/type and an explicit evidence/coverage marker.

Use an additive observation table or similarly versioned source-specific
records, never a shared overwrite-prone `attempt_detail` bucket. The parent
call's status, a failed physical attempt, and a logical turn's terminal outcome
are separate metrics. Missing IDs mean unknown correlation, not a fabricated
one-to-one match. A successful fallback can retain earlier errors without
being counted as a terminal user-visible failure. SDK-internal retries may be
invisible; declare that coverage.

Recognize errors only in protocol-defined response envelopes/events (for
example Anthropic SSE `type=error`, Gemini top-level `error`, OpenAI top-level
`error`, Responses `response.failed` and its error object), not arbitrary
nested tool arguments or generated text. HTTP 200 can carry a semantic error.
A truncated stream without a terminal marker is incomplete evidence unless a
transport error or host callback establishes failure. Safety/refusal signals
are separate from operational errors by default; existing signals preserve
provider refusals and heuristic wording distinctly.

Generalized categories can then distinguish authentication, permission,
rate-limit, quota/billing, invalid/context request, provider/server,
connection/DNS/TLS, timeout, stream/protocol and unknown. Preserve 429 subtypes
and Retry-After only when explicitly observed, with privacy-safe bounded
values. Do not label all quota/billing as 429 or all 429 as exhausted billing.

Historical observations can only be reconstructed from retained hook details,
proxy attempt sequences or raw protocol envelopes. Expired bodies and merged
away attempts are irrecoverable; do not invent category or count precision.
No historical migration should be triggered by read-only API access.

## UI handoff

The frontend can show a general errors badge with recovered/failed/unknown
call distinction while retaining the 429 badge/subcount. Use `scope=call` and
`recorded_failure_observations` labels accurately. Filters should distinguish
any observed error, failed call, and recovered call. Do not label any of these
"failed user turns". Keep explicit sources and an evidence link in detail;
show no raw provider error bodies by default. Per-model/credential physical
attempt totals need the source-aware follow-up before being presented as exact.

## Verification

`tests/test_general_errors.py` exercises the actual hook → SQLite → dashboard/CLI
reader boundaries for 401, 403, 429, 503, timeout/invalid-response sentinels,
pending rows and retry recovery. It also checks all-2xx/legacy unknown
classification and that the new summary emits no message or credential text.
The tests fail against the original backend. The existing CLI shape contract
explicitly records the additive field for old and current stores.
