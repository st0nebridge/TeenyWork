# TeenyWork Challenger: technical documentation

This document describes the Challenger server as the code implements it: the protocol, every HTTP endpoint, the token model, the ledgers, the pool connection, the security model and its limits, and how a website uses the service. [README.md](./README.md) covers setup and [THEORY.md](./THEORY.md) the rationale.

## 1. Components

| Path | Crate | Role |
|---|---|---|
| `server/src/main.rs` | `compute-to-access-server` (binary) | HTTP API (actix-web), challenge/lease/proof/token flow, share ledger, startup checks. |
| `server/src/activity.rs` | same | The activity ledger: replay at startup, lifetime totals and recent events, and the writer thread that commits records in groups. |
| `server/src/stratum_client.rs` | same | Stratum V1 pool connection, job table, extranonce2 leasing, spent access proofs, share submission. |
| `server/src/ledger.rs` | same | Append-only JSON Lines ledgers: one write per record, synced alone or with a group, size-based rotation, tolerant replay. |
| `server/src/expiring.rs` | same | The bounded in-memory tables of live challenges, leases and token grants. |
| `core/src/challenge/` | `compute-to-access-core` | HMAC-SHA-256 challenge issue and verification. |
| `core/src/token/access_token.rs` | same | Random access-token IDs. |
| `core/src/proof/bitcoin.rs` | same | SHA-256d and the 80-byte header. |
| `core/src/stratum/` | same | Header reconstruction from a pool job, access-bit and share-target checks, request builders and the `mining.notify` parser. |
| `wasm-challenger/src/` | `c2a-challenger` (cdylib) | Browser nonce search over a prepared header: the exports (`lib.rs`), the midstate search (`search.rs`), the SHA-256 compression (`sha256.rs`) and its four-lane SIMD form (`lanes4.rs`). It has no runtime dependencies; `sha2` is only the reference its tests compare against. |
| `browser/` | | The demo page (`index.html`), its controller (`controller.js`) and the Web Worker that drives the WASM module (`challenger.js`). |

The crate names, the `C2A_` environment prefix and the `C2A-Pool` worker-name suffix keep the project's original "compute to access" naming; the project itself is TeenyWork.

## 2. Request flow and the `c2a-work/2` protocol

1. The site requests a challenge for a resource (`POST /api/challenge`).
2. A worker requests a lease for that challenge (`POST /api/lease`). The response has `"protocol": "c2a-work/2"` and contains everything needed to build a Bitcoin header:
   - the pool job (`job_id`, `job_generation`, `prev_block_hash`, `coinbase_version`, `coinbase_prefix`, `coinbase_suffix`, `merkle_branches`, `n_time`, `n_bits`);
   - the session's `extranonce_1` and an `extranonce_2` unique to this lease;
   - the access work: `access_solutions` different solutions of `access_difficulty_bits` bits each, which together are the challenge's `access_work_bits` (its `required_work_units`);
   - the pool targets (`pool_difficulty`, `pool_target`) and the limits (`expires_at`, `maximum_runtime_seconds`).
3. The worker builds the header and searches nonces:
   - the coinbase is `coinbase_prefix ‖ extranonce_1 ‖ extranonce_2 ‖ coinbase_suffix`;
   - the merkle root is SHA-256d of the coinbase, folded with each branch;
   - the previous hash has each 4-byte word reversed;
   - version, nTime, nBits and nonce are little-endian.
4. The worker submits candidates (`POST /api/proof`). The server rebuilds each header from its own copy of the leased job (`block_header_for_share`), recomputes SHA-256d and compares it with the submitted `header_hash`.
5. A candidate is a solution when the hash, read in Bitcoin display order (byte-reversed), starts with `access_difficulty_bits` zero bits (`meets_access_bits`). A proof needs `access_solutions` different ones. It meets the pool share target when the reversed hash is no greater than the target derived from the pool difficulty: the difficulty-1 target divided by the difficulty (`pool_share_target`, `meets_difficulty_target`). The two checks are independent.
6. A valid proof returns a single-use token, which the site checks with `GET /protected`.

**Sixteen solutions, not one.** A challenge of `w` bits is asked for as 16 solutions of `w − 4` bits (`access_work_split`; under 5 bits, fewer solutions of at least 1 bit). That is the same expected number of hashes as one solution of `w` bits, 2^w, so a site's difficulty setting keeps its meaning. The time a solve takes varies far less: with one solution, 22% of solves take over 1.5 times the average, 13.5% over twice and 5% over three times; with sixteen, 3.4%, 0.07% and almost none. The sum of 16 waits that each look like a single solve is a gamma distribution with a sixteenth of the variance.

The browser worker (`browser/challenger.js`) searches in chunks of 16,384 nonces for at most `min(60 s, maximum_runtime_seconds)`. The WASM module stops at each solution (`challenger_search` returns at most one access candidate and one pool candidate per call), so the worker starts the next call after it, in nonce order, until it has the lease's solutions. The form search stops there. The pool search then keeps going until it finds a pool-target candidate. The worker reports progress, and yields so a cancel can arrive, every 200 ms.

**The solver.** The first 64 header bytes are the same for every nonce, so `challenger_search` hashes them once per call (the SHA-256 midstate). Each nonce then costs one compression for the rest of the header and one for the second SHA-256, instead of three. Only the hash's last state word is computed in the hot loop; a nonce whose word shows it cannot meet the access bits or the pool target is skipped, and any other nonce is hashed again in full and checked exactly, so the result is the same as checking every hash. The module is built twice, with identical exports and result layout: `wasm-challenger-simd.wasm` hashes four nonces at a time with WebAssembly SIMD, and `wasm-challenger.wasm` is the scalar build. The worker loads the SIMD build when the engine validates it and the server has it, and the scalar build otherwise. A site may ship its own worker that calls these exports directly, so the exports and the 84-byte result layout must not change.

## 3. Endpoints

Request bodies are JSON. A body that does not parse, or lacks a required field, is rejected by actix-web with `400`; a body over 64 KiB with `413`. Error responses are plain text unless they are shown as JSON. "Recorded" means an event is appended to the activity ledger. A ledger write failure returns `500`, and the operation it was recording does not take effect.

### `POST /api/challenge`

Request: `{"resource": "<1-2048 bytes>", "high_confidence_bot": false}` (`high_confidence_bot` is optional).

**Difficulty**
- The base is the configured `required_work_units` (8–24, default 12).
- The path part of the resource (before `?`) raises it to at least 14 for `/search…`, 16 for `/report…` and 18 for `/bulk…`.
- `high_confidence_bot: true` adds 4, capped at 24. It needs `Authorization: Bearer <C2A_API_KEY>`.

| Status | When |
|---|---|
| `200` | Returns `challenge_id`, `resource`, `issued_at`, `expires_at` (15 minutes), `required_work_units`, `algorithm` (`sha256d-leading-zero-bits`), `nonce` and `signature` (hex). Records `challenge_issued`. |
| `400` | Empty or over-long resource, or resource `/`, which needs no challenge. |
| `401` | `high_confidence_bot` without a valid API key. |
| `503` | 50,000 live challenges are already held (`The Challenger is at capacity; try again shortly`). |

The challenge ID is the issue time in microseconds plus 8 bytes of an HMAC-SHA-256 keyed with `C2A_SERVER_SECRET`. The signature is an HMAC-SHA-256 over the ID, resource, work units, nonce and validity window, and is checked again on lease and proof (`verify_challenge`). Challenges are held in memory until they expire.

### `POST /api/lease`

Request: `{"challenge_id": "…", "worker_id": "<1-128 bytes>"}`.

| Status | When |
|---|---|
| `200` | The `c2a-work/2` lease described in section 2, with `algorithm: "bitcoin-sha256d-header"`, a 90-second `expires_at` and `maximum_runtime_seconds: 60`. Records `lease_issued`. |
| `400` | Invalid worker ID; unknown or expired challenge; failed challenge verification. |
| `409` | A live lease already exists for this challenge. |
| `503` | No live pool job, worker not authorized, unsupported extranonce2 size, or every extranonce2 value for the current job is already leased; or 20,000 live leases are already held. |

One live lease per challenge; leases are held by challenge ID. A request refused with `409`, or for lack of room, is refused before an extranonce2 is taken, so refused requests cannot use up the job's range. Each lease gets the next extranonce2 for the current job, encoded big-endian in the pool's negotiated width (1–16 bytes). It never wraps: when the width is used up, leases are refused with `503` until the pool sends a new job, which starts a fresh range.

### `POST /api/proof`

Request:
```json
{"challenge_id": "…", "lease_id": "…", "worker_id": "…",
 "candidates": [{"header_hash": "<64 hex>", "extranonce_2": "…", "n_time": 0, "nonce": 0}],
 "hashes_attempted": 0, "elapsed_ms": 0}
```
`hashes_attempted` and `elapsed_ms` are accepted and ignored: browser-reported work is not trusted. `n_time` comes from the candidate.

Checks run in this order. A proof can only spend the live lease of its own challenge, and only when its `lease_id` and `worker_id` match that lease: a proof naming any other lease leaves it in place. A matching lease is used up by the first proof submitted against it, whatever the outcome.

| Status | When |
|---|---|
| `400` | Unknown or already-used challenge; failed challenge verification; unknown, expired or mismatched lease (wrong challenge or worker); not 1–32 candidates; a candidate whose `extranonce_2` is not the lease's (recorded `proof_rejected`); `header_hash` not 32-byte hex; a header that cannot be built; a hash that does not match the rebuilt header (recorded `proof_rejected`); fewer different candidates meet the lease's bits than it asks for (`Invalid proof of work`, recorded `proof_rejected`; a candidate sent twice counts once); fewer than that many of them are new, because the rest have already earned a token (recorded `proof_rejected`); the challenge was used meanwhile. |
| `409` | The leased job is no longer live in the pool session, with the same job ID and generation. |
| `503` | 50,000 unused token grants are already held. The lease is used up, but the challenge is kept and its work is not marked as rewarded, so the visitor can lease again (unless the table filled while the proof was checked; see section 8). |
| `200` | `{"token": "<64 hex>", "credits_remaining": 1, "expiry": "<RFC 3339>", "pool_share": "<status>"}`. Records `proof_accepted` and consumes the challenge. |

**Replayed work.** Header hashes that earned a token are remembered by the previous-block hash they build on, and a proof must carry the lease's number of solutions among those not yet remembered: old solutions cannot make up the number. They are kept across reconnects, `mining.subscribe` and `mining.set_extranonce`, and dropped once no live job builds on that block. A header hash commits to the job, both extranonces, nTime and nonce, so a repeat is the same work presented again.

**Pool shares.** Each verified candidate that meets the pool share target is recorded as `pool_share_candidate`. Then:
1. It is skipped if its share ID was already submitted. The set of submitted IDs is rebuilt from the share ledger at startup.
2. Otherwise it is written to the share ledger as `submission_pending` and sent to the pool.
3. The server waits up to 5 seconds for the pool's answer, then writes the outcome to the share ledger.

`pool_share` in the response is one of: `not_pool_qualified`, `duplicate_not_forwarded`, `pool_accepted` (recorded `pool_share_accepted`), `pool_rejected` (recorded `pool_share_rejected`), `submission_error: …`, `submission_timeout`, `pool_disconnected`.

### `GET /protected?token=<token>&resource=<resource>`

This is the token check a site makes, server to server.

| Status | When |
|---|---|
| `402` | Missing or empty `token`, whatever the User-Agent or the `Authorization` header, the API key included. The body is JSON: `{"error": "A proof-of-work token is required: …", "protocol": "c2a/1", "resource": <the requested resource or null>, "methods": [{"id": "bitcoin-sha256d", "endpoint": "/api/challenge"}]}`. |
| `400` | A token with a missing or empty `resource`. The token is not used up. |
| `401` | Unknown, already-used or expired token. |
| `403` | The token is for a different resource. The token is not used up. |
| `200` | The first valid call for the token's own resource (`Protected content for <resource>`). The token is removed, then `form_submission_verified` is recorded with the challenge ID and work units. The grant table is not held while that record is written, and the same token presented meanwhile gets `401`. If the record cannot be written, the answer is `500` and the token can be used again. |

### `GET /api/forms/contact` and `POST /api/forms/contact`

`GET` returns `402` with a JSON negotiation body: `protocol`, `resource: "/forms/contact"`, and `methods` (`challenge_endpoint: "/api/challenge"`).

`POST` is the demo form. Request: `{"name": "<1-120>", "email": "<1-254>", "message": "<1-5000>"}`; each field must be non-blank.

| Status | When |
|---|---|
| `400` | Invalid fields. |
| `202` | A valid `Authorization: Bearer <token>` scoped to `/forms/contact`; the API key is not a token. The token is used up as on `/protected`. Returns `{"validated": true, "message": …}` and records `form_submission_verified`. Nothing is stored or sent. |
| `402` | No `Bearer` credential (JSON negotiation body). |
| `401` | Token over 4,096 bytes, unknown, used or expired. |
| `403` | Token for another resource. |

### Administration (bearer `C2A_API_KEY`)

- **`POST /admin/config`** with `{"payout_address": "…", "required_work_units": 8-24}`.
  - The address must look like a Bitcoin mainnet address: base58 starting `1`/`3` with 26–35 characters, or bech32 starting `bc1` with 14–90 characters in a single case.
  - `401` without the key; `400` for invalid values; `500` if the file cannot be saved.
  - On success the server saves the configuration atomically to `C2A_CONFIG_FILE` (temporary file, sync, rename), enables the pool connection and reconnects with the new worker name. It returns `200` with `{"payout_address", "required_work_units", "pool_reconnecting": true}`.
- **`GET /admin/activity`** returns `401` without the key. Otherwise `200` with:
  - `{"totals": {"challenges_distributed", "leases_issued", "proofs_solved", "proofs_rejected", "pool_share_candidates", "pool_shares_accepted", "pool_shares_rejected", "forms_verified"}, "recent_activity": [...]}`;
  - each recent item is `{"occurred_at", "event", "challenge_id", "work_units"}`, up to the latest 100.

### Unauthenticated status endpoints

- **`GET /api/pool`** returns `{connected, authorized, difficulty, has_job, job_id, extra_nonce_1, extra_nonce_2_size}`.
- **`GET /api/job`** returns `503` with `{error, connected, authorized}` until a job exists. Then it returns the current job: `job_id`, `prev_block_hash`, `coinbase_version`, `coinbase_data` (prefix and suffix joined, without extranonces), `coinbase_prefix`, `coinbase_suffix`, `merkle_branches`, `merkle_root`, `n_time`, `n_bits`, `clean_jobs`, `synthetic: false`. `merkle_root` is always empty, because the root depends on each lease's extranonce2.
- **`GET /metrics`** returns Prometheus text: `c2a_challenges_issued`, `c2a_leases_issued`, `c2a_access_proofs_accepted`, `c2a_access_proofs_rejected`, `c2a_pool_share_candidates`, `c2a_pool_shares_accepted`, `c2a_pool_shares_rejected`, `c2a_form_submissions_verified`.
- **`GET /challenge-ui`** redirects (`302`) to `/browser/index.html`.
- **`GET /browser/{file}`** serves only `index.html`, `challenger.js`, `controller.js`, `wasm-challenger.wasm` and `wasm-challenger-simd.wasm`, from the `browser` directory relative to the server's working directory. Anything else, or a missing file, returns `404`.

## 4. Token model

- **Identity.** A token ID is 32 bytes from the operating system's CSPRNG (`getrandom`), as 64 lowercase hex characters. It is not derived from the challenge, the time or the secret.
- **Grant.** The server keeps a grant per token: the challenge's resource, the expiry (one hour), and the challenge ID and work units for the activity ledger.
- **Single use.** The first successful use removes the grant, through either `/protected` or the demo form. Any later use is `401`, the same as an unknown or expired token. A refusal for the wrong resource (`403`), or for a missing resource (`400`), leaves the grant in place.
- **Response field.** `credits_remaining` is always `1`.
- **Lifetime.** Grants live in memory. A restart forgets every unused token, and the visitor solves a new challenge.

## 5. The pool connection (Stratum V1)

- **Starting.** The connection is off until a payout address has been saved (`pool_enabled` in the configuration file). A missing configuration file starts with it off.
- **Connecting.** The client connects to `C2A_POOL_HOST`, over TLS with the webpki root store unless `C2A_POOL_TLS` is `false`. It sends `mining.subscribe` (id 1), then `mining.authorize` (id 2) for the worker `<payout address>.C2A-Pool` with password `x`.
  - Connecting, TLS, subscribe and authorize must finish within 30 seconds.
  - A subscribe error, a non-array subscribe result, invalid extranonce parameters (extranonce1 must be hex; the extranonce2 size must be 1–16) or a refused authorization ends the connection.
- **Messages.** Each message is one JSON line of at most 64 KiB, read with a cancel-safe reader.
  - `mining.set_difficulty` sets the share difficulty, which must be positive and finite.
  - `mining.set_extranonce` replaces extranonce1 and the extranonce2 size, and clears the job table.
  - `mining.notify` is parsed strictly: a missing or non-string job ID, a hash or merkle branch that is not 64 hex characters (at most 32 branches), coinbase parts that are not non-empty even-length hex, or a version, nBits or nTime that is not exactly eight hex digits ends the connection. `clean_jobs` clears older jobs. Every notify gets a new generation number.
- **Submitting shares.** Shares are sent as `mining.submit [worker, job_id, extranonce_2, ntime_hex, nonce_hex]` with request IDs from 3 upward, and replies are matched by ID.
- **Reconnecting.** Any error ends the connection and clears the job table and authorization. The client retries after 5 seconds, or at once if the payout address changes. A payout change also ends a live connection, so the worker name can change.

## 6. Ledgers

Both ledgers are append-only JSON Lines files written through `server/src/ledger.rs`:
- **Writes.** Each record and its newline are written in one write. A torn final line is terminated with a newline when the file is opened, and the live file is synced before it is rotated.
- **Syncs.** The share ledger syncs each record on its own, on the blocking thread pool. The activity ledger has one writer thread that commits records in groups: it writes every record waiting when it wakes (up to 1,024), syncs the file once, then answers each request. A request still continues only once its record is on disk, but concurrent requests share one sync, and no request blocks the async runtime or holds a lock while the disk syncs.
- **Replay.** At startup a malformed line, such as the torn last line a crash can leave, is skipped with a warning and counted. It does not stop the service.
- **Rotation.** Before a record would take the live file past `C2A_LEDGER_MAX_BYTES` (default 16 MiB), the live file becomes `<file>.1`, older files shift to `.2` and `.3`, and `.3` is deleted.

**Activity ledger (`C2A_ACTIVITY_LEDGER`).** Events: `challenge_issued`, `lease_issued`, `proof_accepted`, `proof_rejected`, `pool_share_candidate`, `pool_share_accepted`, `pool_share_rejected`, `form_submission_verified`. Each record holds the time, event, challenge ID and work units. Request IPs, worker IDs and form contents are not recorded. Every new file after a rotation starts with a checkpoint line holding the lifetime totals of everything before it. At startup the totals are the records counted back to the newest intact checkpoint, which stays exact after a crash part-way through a rotation. The latest 100 records come from the retained files. The totals feed `/admin/activity` and `/metrics`.

**Share ledger (`C2A_SHARE_LEDGER`).** For every forwarded share it records `share_id`, `challenge_id`, `lease_id`, `job_id`, `nonce`, `extranonce_2`, `header_hash`, `status` and `recorded_at`: a `submission_pending` record before sending and an outcome record after. Startup rebuilds the set of submitted share IDs from the live and retained files, so a share is never forwarded twice. A share old enough to be rotated out belongs to a pool job that is no longer live, which `/api/proof` already refuses. A restart while a share is `submission_pending` leaves its outcome unknown, and it is not retried.

## 7. Configuration

| Variable | Default | Notes |
|---|---|---|
| `C2A_SERVER_SECRET` | required | At least 32 bytes and not the `.env.example` placeholder; otherwise the server will not start. |
| `C2A_API_KEY` | unset | Optional. If set, it must not be blank or the `.env.example` placeholder, or the server will not start. Shorter than 32 characters only warns. An empty configured key never authenticates. |
| `C2A_POOL_HOST` | `public-pool.io:14333` | |
| `C2A_POOL_TLS` | `true` | `true` or `false`, in any case; any other value stops startup, so a typo cannot fall back to plaintext. |
| `C2A_POOL_USERNAME` | built-in address | Initial payout address when `C2A_CONFIG_FILE` does not exist. |
| `C2A_CONFIG_FILE` | `c2a-config.json` | `{"payout_address", "required_work_units", "pool_enabled"}`. An invalid file stops startup. |
| `C2A_ACTIVITY_LEDGER` | `c2a-activity.jsonl` | |
| `C2A_SHARE_LEDGER` | `c2a-share-ledger.jsonl` | |
| `C2A_LEDGER_MAX_BYTES` | `16777216` | A positive whole number of bytes; anything else stops startup. |
| `C2A_BIND_ADDRESS` | `127.0.0.1:8081` | |

## 8. Security model and known limits

- **The browser is untrusted.** The server rebuilds every header from its own job copy and checks it. It accepts only the lease's extranonce2, refuses a stale job generation (`409`), and refuses work that has already earned a token. It ignores reported hash counts.
- **Tokens are bearer secrets.** They are unguessable and single-use, scoped to one resource, and valid for an hour. `/protected` takes the token in the query string, so it is meant for server-to-server calls; don't log query strings on that path.
- **Admin authentication.** The API key is compared in constant time (`subtle`). An empty or placeholder key cannot be configured. The key opens the administration routes and elevated challenges only; it is not a token for `/protected` or the demo form.
- **Exposure.** `/metrics`, `/api/pool` and `/api/job` are unauthenticated. The challenge, lease and proof endpoints are unauthenticated and have no rate limiting of their own, and every issued challenge and lease is a ledger write, synced in groups. Rotation bounds disk use but not request rate. The tables are bounded: at most 50,000 live challenges, 20,000 live leases and 50,000 unused token grants, swept of expired entries at most once a second, and JSON bodies of at most 64 KiB. A full table answers `503`, which the site should treat as the Challenger being unavailable. The remembered solutions (section 3, *Replayed work*) are not capped: every accepted proof adds up to 32 header hashes, kept until no live job builds on that block, so their memory grows with the rate of accepted proofs within a block. Keep the service on loopback behind the site, and rate-limit there.
- **Forms depend on the pool.** Leases need a connected, authorized pool session with a live job. If the pool is down, or the payout address has not been saved, `/api/lease` returns `503` and a protected form cannot be verified.
- **Access and share targets are separate.** An access proof needs work of 8–24 bits (16 solutions of 4–20 bits), which a browser finds in seconds. A pool share needs the pool's target, far beyond what a browser finds in practice. Most access proofs are never shares, and pool acceptance is not a payout.
- **Single process, in memory.** Challenges, leases, tokens and the spent-proof set are not persisted, and the server is not horizontally scalable. After a restart, a pool that re-issued the same extranonce1 and the same job could see an earlier solution accepted once more, because the spent set starts empty.
- **Extranonce2 exhaustion.** A pool with a very small width (one byte gives 256 leases per job) refuses leases with `503` until its next job. Every lease takes the next value, including a new lease for the same challenge and a lease whose proof is refused, so a client that leases repeatedly can use up a narrow range; rate-limit lease requests at the site.
- **Capacity during a proof.** The token table's room is checked before a proof's work is spent, but the token is added only after the ledger record and any pool submission. If the table fills in between, the proof answers `503` with its challenge and solutions already used.

## 9. How a site uses the Challenger

Browsers need only three routes: `POST /api/lease`, `POST /api/proof` and `GET /browser/…` for the solver. A site that lets browsers reach them through its own origin should forward only those, strip any `Authorization` header, and rate-limit them. Everything else stays server to server: minting challenges (so the site makes the `high_confidence_bot` decision), `/protected`, `/admin/*`, `/metrics`, `/api/pool` and `/api/job`.

A site calls the Challenger server to server:
- **Challenges and leases.** `POST /api/challenge` with `resource` and `high_confidence_bot`. Send the bearer key only when `high_confidence_bot` is true. Then `POST /api/lease`, whose answer has `protocol: "c2a-work/2"`; a worker should check it before it searches. `c2a-work/1`, the one-solution protocol before 0.2.0, is no longer issued.
- **Proofs.** `POST /api/proof`. Treat an answer without a non-empty `token` as a failed proof.
- **Token check.** `GET /protected?token=…&resource=…` without an `Authorization` header. `200` means valid; `401`, `402` and `403` mean invalid; treat any other status as an error. A site that caches the results should check each (resource, token) pair at most once, so its cache and the Challenger's single-use rule agree.
- **Administration.** `POST /admin/config` with the API key, to save the payout address and difficulty. `GET /admin/activity` with the key, for the eight totals and the recent events described in section 3. A site that shows them should check the totals and the event names (section 6) before it does.
- **Status and the solver.** `GET /api/pool` for pool status. `GET /browser/wasm-challenger-simd.wasm` and `GET /browser/wasm-challenger.wasm` for the browser solver, which a site may cache. A `404` for the SIMD build means the Challenger has none, and a worker then uses the scalar build.

## 10. Tests

| Location | Covers |
|---|---|
| `server/src/hardening_tests.rs` | Full challenge, lease and token tables answer `503` (a full token table before the challenge is spent); a refused lease takes no extranonce2; a proof cannot spend another challenge's lease; JSON bodies over 64 KiB get `413`; `C2A_POOL_TLS` accepts only `true`/`false`; the listener answers HTTP/1.1 only. |
| `server/src/expiring.rs` | Table capacity, replacement, once-a-second sweeps, a clock that goes back. |
| `server/src/main.rs` | `protected_access_tests` (the `/protected` contract, single use, random token IDs, verified-form counting, the API key opening neither token route, the demo form's field limits, the grant table left free while a record is written), `access_proof_replay_tests` (work split into 16 solutions; a lease asks for them; 16 different solutions earn a token, 15, one sent 16 times, or honest misses do not; solutions that earned a token do not count again beside a new one; a one-byte extranonce2 never wraps; a solution cannot earn a second token after a counter reset), `startup_secret_tests`, `share_ledger_tests` (torn and malformed lines, rotation, writes off the async runtime), `pool_runtime_config_tests`. |
| `server/src/activity.rs` | Torn and malformed lines, rotation, totals across a crash, checkpoints only at the top of a file, how far startup reads older files, the 100 newest records, group commit (one sync per group, at most 1,024 records), and a dropped log finishing its queue. |
| `server/src/ledger.rs` | Single-write records, replay, torn-line handling, rotation boundaries, one sync per group, a sync before rotation, the cap setting. |
| `server/src/stratum_client.rs` | Extranonce2 bounds and per-job restart, the spent-proof set (a proof needs its number of new hashes; a refused proof spends nothing), the handshake timeout, the line limit, non-array subscribe results, and a full subscribe/authorize/notify/submit exchange with a local fake pool. |
| `core/src/*/tests.rs`, `core/src/stratum/bitcoin_job.rs` | Challenges, token IDs, the 80-byte header, `mining.notify` parsing against a realistic fixture and malformed variants, header reconstruction, targets. |
| `wasm-challenger/src/tests.rs` | The batch search and target comparison; the midstate hash and last word against `sha2`; the search against a `sha2` reference search over 400 random cases. |
| `tests/regression/challenger-runtime.test.mjs` | The browser worker's 60-second work window. |
| `tests/regression/wasm-solver-equivalence.test.mjs` | Both release builds, through their exports, against a one-hash-at-a-time SHA-256d search (the only test of the SIMD build), and that both export the same functions. |
| `tests/regression/challenger-worker.test.mjs` | The worker picks the SIMD build, falls back to the scalar one when it is missing or invalid, sends the first 16 solutions in nonce order (each rebuilt into a valid header in Node), refuses a `c2a-work/1` lease, goes on to a pool share in a pool search, and stops on a cancel. |
