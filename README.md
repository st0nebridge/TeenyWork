# TeenyWork

> **Proof of concept: use at your own risk.** TeenyWork is an experiment, not production software. It has had no independent security audit, it does real Bitcoin mining work against a live pool, and it comes with no warranty or support. You are responsible for how and where you run it.

TeenyWork is a proof-of-work gate for web forms whose work is real Bitcoin mining. When someone submits a protected form, their browser spends a few seconds searching Bitcoin SHA-256d block headers built from a live Stratum V1 pool job. The **Challenger** server (this repository) checks the result and issues a single-use access token, which the site checks before it accepts the form. If a result also happens to meet the pool's much harder share target, the Challenger forwards it to the pool.

Three outcomes are kept separate:
- a valid access proof, which unlocks one form submission;
- a pool-accepted share, which only the pool can confirm;
- an eventual BTC payout, which the pool's accounting decides.

Most access proofs are never pool shares. [THEORY.md](./THEORY.md) covers the rationale, the probability model and the ethical position. The intended use is bounded computation that the visitor's own form submission starts, not hidden or persistent background mining.

TeenyWork runs behind a website, which requests challenges for its forms and checks the tokens. [DOCUMENTATION.md](./DOCUMENTATION.md) is the reference for the protocol, every endpoint, the token model, the ledgers and the security model.

## How it works

1. **Challenge.** `POST /api/challenge` with a resource such as `/forms/contact` returns a signed challenge. It is bound to that resource and to its work in bits (8–24, default 12): the expected number of hashes is 2 to that power.
2. **Lease.** `POST /api/lease` assigns the challenge an exclusive slice of the current pool job: the job's coinbase parts and merkle branches, the pool's extranonce1, and an extranonce2 unique to this lease. The lease lasts 90 seconds and tells the browser to search for at most 60. It asks for 16 solutions of 4 bits fewer than the challenge (protocol `c2a-work/2`): the same work on average as one solution of the full bits, but a solve takes much the same time every time instead of sometimes several times the average.
3. **Search.** The browser builds the 80-byte block header and searches nonces in a Web Worker ([browser/challenger.js](./browser/challenger.js)). The hashing loop runs in a small Rust WebAssembly module (`wasm-challenger`), which hashes the fixed first 64 header bytes once per batch. It comes in two builds with the same exports: a SIMD build that hashes four nonces at a time, which the worker prefers, and a scalar build for engines without WebAssembly SIMD.
4. **Proof.** `POST /api/proof` sends the solutions' nonces and header hashes. The server rebuilds each header from its own copy of the leased job and recomputes SHA-256d. It counts the different solutions that meet the bits, requires the lease's number of them that have not already earned a token, then forwards any candidate that meets the pool's share target.
5. **Token.** A valid proof returns a token: 256 random bits, valid for one hour and for one use, on the challenge's resource only.
6. **Check.** The site calls `GET /protected?token=<token>&resource=<resource>`. The first valid call returns `200` and uses the token up. A later call returns `401`. A call for a different resource returns `403` and leaves the token usable. A missing token returns `402`.

The pool connection stays off until an administrator saves a payout address through the authenticated `POST /admin/config`. Until then no leases can be issued.

## Configuration

All settings are environment variables. The names keep the project's original `C2A_` ("compute to access") prefix. The Rust crates also keep their original names: `compute-to-access-core`, `compute-to-access-server` and `c2a-challenger`.

| Variable | Default | Meaning |
|---|---|---|
| `C2A_SERVER_SECRET` | none, required | Signs challenges. At least 32 bytes. The server refuses to start with the `.env.example` placeholder. |
| `C2A_API_KEY` | unset | Bearer key for `/admin/config`, `/admin/activity` and elevated (high-confidence bot) challenges; unset disables those. The server refuses to start if it is set but empty, or is the `.env.example` placeholder. A key shorter than 32 characters only logs a warning. |
| `C2A_POOL_HOST` | `public-pool.io:14333` | Stratum V1 pool as `host:port`. |
| `C2A_POOL_TLS` | `true` | Use TLS to the pool. Set `false` to connect in plaintext. Only `true` and `false` (in any case) are accepted; any other value stops startup. |
| `C2A_POOL_USERNAME` | `UNSET-PAYOUT-ADDRESS` | Initial payout address when no configuration file exists yet. The pool stays off until an address is saved through `/admin/config`. The default is a placeholder, not an address: `/admin/config` refuses it, a configuration file that turns the pool on with it stops startup, and the pool client will not connect with it. |
| `C2A_CONFIG_FILE` | `c2a-config.json` | Where `/admin/config` saves the payout address and base difficulty. |
| `C2A_ACTIVITY_LEDGER` | `c2a-activity.jsonl` | Activity ledger: the activity totals and recent events. |
| `C2A_SHARE_LEDGER` | `c2a-share-ledger.jsonl` | Record of every pool share forwarded and its outcome. |
| `C2A_LEDGER_MAX_BYTES` | `16777216` (16 MiB) | Size at which each ledger file rotates. The live file plus three rotated files are kept. |
| `C2A_BIND_ADDRESS` | `127.0.0.1:8081` | Address the HTTP API listens on. |

`.env.example` lists the two secrets. Generate each one independently, for example with `python -c "import secrets; print(secrets.token_hex(32))"`.

## Running locally

```powershell
rustup target add wasm32-unknown-unknown

# Build both browser solvers (scalar and SIMD) and put them where the server serves them from
cargo build --release -p c2a-challenger --target wasm32-unknown-unknown
$env:RUSTFLAGS = "-C target-feature=+simd128"
cargo build --release -p c2a-challenger --target wasm32-unknown-unknown --target-dir target\wasm-simd
Remove-Item Env:RUSTFLAGS
Copy-Item target\wasm32-unknown-unknown\release\c2a_challenger.wasm browser\wasm-challenger.wasm
Copy-Item target\wasm-simd\wasm32-unknown-unknown\release\c2a_challenger.wasm browser\wasm-challenger-simd.wasm

# Two independent random secrets
$env:C2A_SERVER_SECRET = python -c "import secrets; print(secrets.token_hex(32))"
$env:C2A_API_KEY = python -c "import secrets; print(secrets.token_hex(32))"

cargo run -p compute-to-access-server
```

Run the server from the repository root: it serves the browser files from `browser/` relative to its working directory. The demo form is at `http://127.0.0.1:8081/challenge-ui`. Before it can lease work, save a payout address and difficulty:

```powershell
$body = '{"payout_address":"<a Bitcoin mainnet address>","required_work_units":12}'
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8081/admin/config `
  -Headers @{ Authorization = "Bearer $env:C2A_API_KEY" } -ContentType application/json -Body $body
```

Don't use a production payout address or production secrets for local testing. To test without a real pool, point `C2A_POOL_HOST` at a local Stratum endpoint and set `C2A_POOL_TLS=false`.

The demo page has two modes. The default mode verifies the form with one access proof and shows progress. It also has a separate, opt-in pool search, which keeps searching fresh leases until it is stopped or the pool answers a full-target share. Each pool-search batch is a proof for `/pool/share-search`, which the Challenger checks, records and forwards like any other but which earns no token. `/browser/index.html?mode=minimal` hides the panels and submits the form only after the pool accepts a share. At real pool difficulty a browser is not expected to find one in practical time. The minimal mode's batches are `/pool/share-search` proofs as well; once the pool accepts a share, the worker that found it solves one ordinary `/forms/contact` proof, and that proof's token submits the form. Both modes ask for their challenges from the browser, which a site keeps server to server ([DOCUMENTATION.md](./DOCUMENTATION.md) section 9), so the demo page is for local testing.

## Testing

```powershell
cargo test --workspace
cargo build --locked --release -p compute-to-access-server
# The Node tests load both solver builds (see Running locally for the SIMD build)
cargo build --locked --release -p c2a-challenger --target wasm32-unknown-unknown
node --test --test-timeout=120000 --test-force-exit "tests/regression/*.test.mjs"
```

The Rust tests live beside the code in `#[cfg(test)]` modules:
- **Server (`server/src/main.rs`):** the `/protected` contract and token model, proof replay, share forwarding and the pool's answers, startup secrets, the share ledger. `server/src/activity.rs` covers the activity ledger and its group commit, `server/src/ledger.rs` the ledger files; `server/src/hardening_tests.rs` covers the capacity limits (remembered solutions included), lease ownership and the 8 leases per challenge, the token slot a proof holds, pool-search proofs, the JSON body cap and `C2A_POOL_TLS`; `server/src/expiring.rs` the bounded tables.
- **Stratum client (`server/src/stratum_client.rs`):** lease allocation and the narrow-extranonce2 warning, the remembered solutions and their cap, the pool handshake and line limits, share submission against a local fake pool.
- **Core crate:** challenges, tokens, header reconstruction, `mining.notify` parsing.
- **WASM crate:** the search loop, held to a straightforward `sha2` search over random work.

The Node tests check that the browser worker honours the server's 60-second work window, that the demo page's minimal mode searches with token-free batches and asks for one form challenge only once the pool accepts a share, that both solver builds return exactly what a one-hash-at-a-time SHA-256d search returns (the Rust tests run natively, so this is where the SIMD build is tested), and that the worker picks the SIMD build, falls back to the scalar one, produces a proof that verifies, and stops on a cancel.

Mutation testing uses `cargo-mutants`; `.cargo/mutants.toml` lists the excluded mutants and why. On Windows pass `--gitignore true` so that ignored folders, which can hold symlinks, are not copied:

```powershell
cargo mutants --gitignore true --file wasm-challenger/src/search.rs --file wasm-challenger/src/sha256.rs --file wasm-challenger/src/lib.rs
```

`node tests/bench/miner-throughput.mjs [seconds] [rounds] [other.wasm ...]` measures each build's hash rate, alternating builds so background load hits them alike; pass an older build to compare against it.

## Running with Docker Compose

Run the Challenger on the same host as the website it protects, behind it, so that only that site talks to it. The Compose file publishes its API on the host's loopback interface only. The image builds the server and the WASM solver from this workspace, and ships only the browser files the server serves. The configuration file and both ledgers live in a named volume.

1. Copy `.env.example` to `.env` and replace both placeholders with independently generated secrets. Keep `.env` private and backed up.
2. `docker compose up --build -d`, then check `docker compose ps`; the health check polls `/api/pool`.
3. Give the site the Challenger's loopback URL and the same `C2A_API_KEY`, then save a payout address through `POST /admin/config`. Saving the address starts the pool connection.

Never expose the Challenger port beyond loopback. `/metrics`, `/api/pool` and `/api/job` are unauthenticated, and the challenge, lease and proof endpoints have no rate limiting of their own. The Challenger caps its tables (50,000 live challenges, 20,000 live leases, 50,000 unused tokens, 800,000 solutions remembered against replay, 64 KiB JSON bodies) and answers `503` when one is full, which the site should treat as unavailable; a challenge gets at most 8 leases. The caps bound memory, not request rates, so the rate limiting belongs to the site in front. Browsers need only `POST /api/lease`, `POST /api/proof` and the solver files under `/browser/`; [DOCUMENTATION.md](./DOCUMENTATION.md) section 9 lists what a site should forward and what stays server to server.

## Licence

MIT. Copyright (c) 2026 Brandon Stonebridge. [LICENSE](./LICENSE) holds the full terms.

TeenyWork is a proof of concept, provided as is and without warranty of any kind. Use it at your own risk.
