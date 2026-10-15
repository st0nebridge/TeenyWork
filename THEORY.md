# TeenyWork: A Theory of Request-Triggered Distributed Mining

## Abstract

TeenyWork studies whether computation already performed during a web form proof-of-work (PoW) challenge can instead search authentic Bitcoin SHA-256d mining work. A browser receives a bounded assignment derived from a current Stratum V1 pool job, searches candidate block headers, and returns candidate results to a coordinating server. The server reconstructs and verifies each candidate, grants form access when the access target is met, and forwards only candidates that also meet the pool's share target.

The proposal is a small-scale systems experiment, not a claim that form traffic can produce meaningful or predictable revenue. Its central hypothesis is that short, request-triggered work from many clients can be coordinated safely and may occasionally yield a pool-accepted share. The theory below separates access proof from mining reward, describes the probability model, and states the project's ethical position and constraints.

## 1. From proof of work to request work

Proof of work turns a search for a value satisfying a computational predicate into evidence that computation was performed. Bitcoin uses repeated double-SHA-256 hashing of candidate block headers: a hash must be numerically no greater than a target. Under the usual idealized model that SHA-256 outputs are uniformly distributed, each new nonce trial is an independent attempt with success probability approximately `target / 2^256` [1].

TeenyWork reuses this search structure within an existing form challenge. The client does not choose the mining job or decide whether a result is valid. A coordinating server obtains pool work, assigns bounded search space, verifies submitted candidates against that work, and handles pool communication. This separates three predicates which are often conflated:

1. **Access proof:** the candidate meets the site's configured, intentionally low challenge target.
2. **Pool share:** the candidate meets the stricter target currently assigned by the pool.
3. **Payout:** the pool's accounting rules eventually allocate funds to the configured payout identity.

Meeting one predicate does not imply meeting the next. In particular, solving a form challenge is not a pool share and does not guarantee revenue.

## 2. Work allocation and aggregation

For a target that requires `k` leading zero bits, the idealized success probability per hash is `2^-k`, so expected work to one success is `2^k` hashes. For an arbitrary 256-bit target `T`, the corresponding probability is `(T + 1) / 2^256`, subject to the implementation's hash byte-order convention.

If a pool distributes work with share target `T_pool`, and eligible workers collectively perform `H` valid, non-stale hashes, the probability of at least one pool share is:

```text
1 - (1 - (T_pool + 1) / 2^256)^H
```

For very small per-hash probabilities this is approximately `H * (T_pool + 1) / 2^256`. Aggregation can make a rare event more likely across many requests, but it does not make any one request likely to find a share. Real work also expires when pool jobs change, so elapsed time, stale work, worker availability, and duplicate submissions reduce useful aggregate effort.

This is pooled mining at the systems level: workers search portions of a pool-provided job, while a central component verifies and submits candidate shares. Pool shares are evidence of partial work against the pool's target; they are not Bitcoin blocks. Pool reward allocation depends on the pool's scheme, its accounting, and whether a submitted share is accepted. Rosenfeld's analysis of pooled-mining reward systems describes why reward allocation is a separate protocol and incentive problem [2]. TeenyWork records share outcomes but cannot promise acceptance, a payout, or a particular payout time.

## 3. Why a form challenge is a distinct operating regime

Conventional mining devices often work continuously and are provisioned for sustained hashing. A form challenge instead creates brief, irregular sessions whose compute capacity and duration are controlled by the client environment. This difference is central to the experiment:

- access work is deliberately bounded and tuned for request latency;
- an access target is generally far easier than a pool share target;
- a request can produce a valid access proof without producing any pool-qualified share;
- browser workers can disappear, throttle, or lose their job before returning a candidate;
- the verifier, not browser-reported hash-rate telemetry, is the authority on whether a candidate is valid.

The expected economic value cannot be inferred from the number of challenges or claimed hashes alone. It requires measuring accepted pool shares, stale/rejected work, request volume, useful hash throughput, pool fees and reward allocation, plus the infrastructure and electricity costs borne by all participating parties. Low direct operating cost to the service is not the same as zero social or energy cost.

## 4. Trust and correctness model

The browser is an untrusted worker. It may submit incorrect, duplicated, delayed, or fabricated claims. Accordingly, the server must reconstruct the candidate header from its own pool job and the assigned lease, recompute SHA-256d, check the target and job freshness, and deduplicate submissions before forwarding a pool-target candidate. Only the upstream pool can confirm share acceptance.

The coordinating service is trusted to select work, enforce configured limits, preserve pool credentials and payout configuration, and report outcomes honestly. A production design also needs authenticated administrative configuration, protected signing secrets, bounded leases, durable records for operational events, and a loopback- or otherwise restricted service boundary. Stratum V1 is widely implemented but described in community documentation rather than a formal Bitcoin Improvement Proposal; implementations therefore need to follow the behavior of their selected pool and test the full request/response path [3].

These controls support verifiable contribution, not a claim that every unit of browser compute is independently auditable. A browser's claimed number of attempts is not a proof of work and must not be used as a basis for payout.

## 5. Ethical position and operating conditions

TeenyWork's ethical position is that **using Bitcoin proof-of-work as a form challenge is not inherently ethically different from using conventional cryptographic proof-of-work for a form challenge**. Both ask a client to perform cryptographic computation to satisfy an access condition. Choosing Bitcoin's SHA-256d work changes the computation and gives pool-qualified results potential mining value, but that difference alone does not make the request ethically worse than a conventional form PoW. The ethical questions concern how the work is disclosed, bounded, and authorized—not whether the challenge work can also contribute to mining.

That position is conditional, not a defense of covert cryptomining. TeenyWork's intended deployment is request-triggered and bounded: computation begins as part of an explicit form submission, uses a server-defined challenge and lease, and stops on completion, timeout, error, or page closure. Ethical operation additionally calls for clear disclosure that the request uses the client's compute for proof-of-work, a reasonable and measurable work/latency limit, no hidden persistent background work, no collection of form contents for mining, and compliance with the device owner's policies and applicable law.

This distinction matters because in-browser cryptojacking research studies mining that runs without the user's informed authorization and documents it as a security and resource-abuse problem [4]. TeenyWork rejects that model. If a deployment cannot provide meaningful notice and respect the resource owner's choice, it does not satisfy the project's ethical premise. A site's choice to apply the challenge, and the effects on accessibility, battery, thermal load, bandwidth, and users with constrained devices, remain subjects for product evaluation rather than assumptions that PoW is harmless.

## 6. Research questions and limitations

The current implementation is a prototype, not a measured proof of economic viability or a general-purpose distributed compute market. Evaluation should answer:

1. What fraction of issued challenges are completed, abandoned, expired, or rejected?
2. How much useful, server-verified work is returned before pool jobs expire?
3. How often are pool-target candidates accepted, and how do pool rules translate those shares into actual account credit?
4. What latency, client resource use, and accessibility costs do users experience at each challenge intensity?
5. Does the service remain secure and operational under malicious clients, replay attempts, stale jobs, and service restarts?

Until those quantities are measured over representative workloads, claims about earnings, carbon impact, or "zero-cost" mining are speculative. The project makes no promise of profit and treats user resource consumption as a real cost even where the service operator pays little for it directly.

## References

1. S. Nakamoto, “Bitcoin: A Peer-to-Peer Electronic Cash System,” 2008. [bitcoin.org/bitcoin.pdf](https://bitcoin.org/bitcoin.pdf).
2. M. Rosenfeld, “Analysis of Bitcoin Pooled Mining Reward Systems,” 2011. [arXiv:1112.4980](https://arxiv.org/abs/1112.4980).
3. “Stratum mining protocol,” Bitcoin Wiki, community-maintained protocol reference. [en.bitcoin.it/wiki/Stratum_mining_protocol](https://en.bitcoin.it/wiki/Stratum_mining_protocol).
4. M. Saad and D. Mohaisen, “Analyzing In-Browser Cryptojacking,” *IEEE Transactions on Dependable and Secure Computing*, 2024. [doi:10.1109/TDSC.2024.3377533](https://doi.org/10.1109/TDSC.2024.3377533).
