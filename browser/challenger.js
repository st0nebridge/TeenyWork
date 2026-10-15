/**
 * @module challenger
 * @description Web Worker that solves a Challenger work lease: builds the
 * Bitcoin header from the leased pool job and searches nonces with the WASM
 * solver, preferring its SIMD build and falling back to the scalar one. A
 * lease asks for several solutions (`access_solutions`, each of
 * `access_difficulty_bits`); the search collects them in nonce order, and a
 * pool search then goes on looking for a pool share.
 *
 * @input Messages init, solve (a c2a-work/2 lease), solve-pool-batch, cancel-solve.
 * @output Messages ready, progress, proof, empty-batch, error.
 * @dependencies /browser/wasm-challenger-simd.wasm or /browser/wasm-challenger.wasm
 */
const MAX_SAFE_NONCE = 0xffffffff;
const WASM_OUTPUT_BYTES = 84;
const SOLVE_CHUNK_SIZE = 16384;
const MAX_SOLVE_RUNTIME_MS = 60_000;
// How often the search reports progress and yields so a cancel can arrive.
// Browsers clamp a chain of zero-delay timers to at least 4 ms, so yielding
// on a timer instead of every 65,536 hashes keeps that cost near 2%.
const PROGRESS_INTERVAL_MS = 200;
const SIMD_MODULE_URL = '/browser/wasm-challenger-simd.wasm';
const SCALAR_MODULE_URL = '/browser/wasm-challenger.wasm';
let cancelled = false;
let wasm = null;

function fromHex(value) {
    if (typeof value !== 'string' || !/^(?:[0-9a-fA-F]{2})*$/.test(value)) {
        throw new Error('Pool job contains invalid hexadecimal data');
    }
    return Uint8Array.from(value.match(/.{2}/g) || [], byte => parseInt(byte, 16));
}

function encodeHex(bytes) {
    return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}

function encodeU32LE(value) {
    return new Uint8Array([value, value >>> 8, value >>> 16, value >>> 24]);
}

function reverseWords(bytes) {
    if (bytes.length % 4 !== 0) throw new Error('Pool previous block hash has invalid length');
    const result = bytes.slice();
    for (let offset = 0; offset < result.length; offset += 4) {
        result.set(result.slice(offset, offset + 4).reverse(), offset);
    }
    return result;
}

function concat(...parts) {
    const joined = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
    let offset = 0;
    for (const part of parts) {
        joined.set(part, offset);
        offset += part.length;
    }
    return joined;
}

async function sha256d(bytes) {
    const firstHash = await crypto.subtle.digest('SHA-256', bytes);
    return new Uint8Array(await crypto.subtle.digest('SHA-256', firstHash));
}

async function fetchModule(url) {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`WASM challenger request failed (${response.status})`);
    return response.arrayBuffer();
}

// The SIMD build hashes four nonces per step. An engine without WebAssembly
// SIMD rejects it in validation, and a server without it answers 404; either
// way the scalar build, which has the same exports, is used instead.
async function loadSolverModule() {
    try {
        const simd = await fetchModule(SIMD_MODULE_URL);
        if (WebAssembly.validate(simd)) return { bytes: simd, variant: 'simd' };
    } catch (error) {
        // Fall through to the scalar build.
    }
    return { bytes: await fetchModule(SCALAR_MODULE_URL), variant: 'scalar' };
}

async function initializeWasm() {
    const { bytes, variant } = await loadSolverModule();
    const { instance } = await WebAssembly.instantiate(bytes);
    const { memory, challenger_alloc, challenger_dealloc, challenger_search } = instance.exports;
    if (!(memory instanceof WebAssembly.Memory) ||
        typeof challenger_alloc !== 'function' ||
        typeof challenger_dealloc !== 'function' ||
        typeof challenger_search !== 'function') {
        throw new Error('WASM challenger exports are invalid');
    }
    wasm = { memory, challenger_alloc, challenger_dealloc, challenger_search, variant };
}

async function calculateMerkleRoot(lease) {
    let root = await sha256d(concat(
        fromHex(lease.coinbase_prefix),
        fromHex(lease.extranonce_1),
        fromHex(lease.extranonce_2),
        fromHex(lease.coinbase_suffix)
    ));
    for (const branch of lease.merkle_branches) {
        root = await sha256d(concat(root, fromHex(branch)));
    }
    return root;
}

function createHeader(lease, merkleRoot, nonce) {
    const version = encodeU32LE(lease.coinbase_version);
    const prevHash = reverseWords(fromHex(lease.prev_block_hash));
    const nTime = encodeU32LE(lease.n_time);
    const nBits = encodeU32LE(lease.n_bits);
    const header = concat(version, prevHash, merkleRoot, nTime, nBits, encodeU32LE(nonce));
    if (header.length !== 80) throw new Error('Constructed Bitcoin header is not 80 bytes');
    return header;
}

function readWasmResult(outputPointer) {
    const view = new DataView(wasm.memory.buffer, outputPointer, WASM_OUTPUT_BYTES);
    const readCandidate = (flagOffset, nonceOffset, hashOffset) => {
        if (view.getUint32(flagOffset, true) === 0) return null;
        const hash = new Uint8Array(wasm.memory.buffer, outputPointer + hashOffset, 32);
        return { nonce: view.getUint32(nonceOffset, true), header_hash: encodeHex(hash) };
    };
    return {
        hashesAttempted: view.getUint32(0, true),
        access: readCandidate(4, 8, 12),
        pool: readCandidate(44, 48, 52)
    };
}

async function solve(lease, poolSearch) {
    if (!lease || lease.protocol !== 'c2a-work/2' ||
        !Number.isInteger(lease.access_difficulty_bits) ||
        lease.access_difficulty_bits < 1 || lease.access_difficulty_bits > 32 ||
        !Number.isInteger(lease.access_solutions) ||
        lease.access_solutions < 1 || lease.access_solutions > 32 ||
        !Number.isInteger(lease.n_time) || !Number.isInteger(lease.n_bits)) {
        throw new Error('Invalid proof-of-work assignment');
    }

    const merkleRoot = await calculateMerkleRoot(lease);
    const shareTarget = fromHex(lease.pool_target);
    if (shareTarget.length !== 32) throw new Error('Pool share target must be 32 bytes');
    const header = createHeader(lease, merkleRoot, 0);
    const headerPointer = wasm.challenger_alloc(header.length);
    const targetPointer = wasm.challenger_alloc(shareTarget.length);
    const outputPointer = wasm.challenger_alloc(WASM_OUTPUT_BYTES);
    if (!headerPointer || !targetPointer || !outputPointer) {
        if (headerPointer) wasm.challenger_dealloc(headerPointer, header.length);
        if (targetPointer) wasm.challenger_dealloc(targetPointer, shareTarget.length);
        if (outputPointer) wasm.challenger_dealloc(outputPointer, WASM_OUTPUT_BYTES);
        throw new Error('Unable to allocate WASM challenger memory');
    }
    new Uint8Array(wasm.memory.buffer, headerPointer, header.length).set(header);
    new Uint8Array(wasm.memory.buffer, targetPointer, shareTarget.length).set(shareTarget);

    const startedAt = performance.now();
    let nextProgressAt = startedAt + PROGRESS_INTERVAL_MS;
    const maxRuntimeMs = Math.min(MAX_SOLVE_RUNTIME_MS, lease.maximum_runtime_seconds * 1000);
    const solutions = [];
    const expectedHashes = lease.access_solutions * 2 ** lease.access_difficulty_bits;
    let poolCandidate = null;
    let hashesAttempted = 0;
    try {
        while (hashesAttempted < MAX_SAFE_NONCE &&
            performance.now() - startedAt < maxRuntimeMs && !poolCandidate) {
            if (cancelled) return;
            // A search stops at each solution, so the next one starts after it;
            // once the solutions are in, a pool search looks only for a share.
            const collecting = solutions.length < lease.access_solutions;
            if (!collecting && !poolSearch) break;
            const nonceCount = Math.min(SOLVE_CHUNK_SIZE, MAX_SAFE_NONCE - hashesAttempted);
            const error = wasm.challenger_search(
                headerPointer,
                targetPointer,
                lease.access_difficulty_bits,
                hashesAttempted,
                nonceCount,
                collecting ? 0 : 1,
                outputPointer
            );
            if (error !== 0) throw new Error(`WASM challenger search failed (${error})`);

            const result = readWasmResult(outputPointer);
            hashesAttempted += result.hashesAttempted;
            if (collecting && result.access) {
                solutions.push({
                    ...result.access,
                    extranonce_2: lease.extranonce_2,
                    n_time: lease.n_time
                });
            }
            if (result.pool) {
                poolCandidate = {
                    ...result.pool,
                    extranonce_2: lease.extranonce_2,
                    n_time: lease.n_time
                };
            }

            const now = performance.now();
            if (now >= nextProgressAt) {
                nextProgressAt = now + PROGRESS_INTERVAL_MS;
                self.postMessage({
                    type: 'progress',
                    data: {
                        attempts: hashesAttempted,
                        poolSearch,
                        percentage: poolSearch
                            ? 0
                            : Math.min(99, hashesAttempted / expectedHashes * 100)
                    }
                });
                await new Promise(resolve => setTimeout(resolve, 0));
            }
        }
    } finally {
        wasm.challenger_dealloc(headerPointer, header.length);
        wasm.challenger_dealloc(targetPointer, shareTarget.length);
        wasm.challenger_dealloc(outputPointer, WASM_OUTPUT_BYTES);
    }

    if (cancelled) return;
    if (solutions.length < lease.access_solutions && poolSearch) {
        self.postMessage({
            type: 'empty-batch',
            data: {
                hashes_attempted: hashesAttempted,
                elapsed_ms: Math.round(performance.now() - startedAt)
            }
        });
        return;
    }
    if (solutions.length < lease.access_solutions) {
        throw new Error(`Found ${solutions.length} of ${lease.access_solutions} access proofs within the ` +
            `${Math.floor((performance.now() - startedAt) / 1000)}s work lease`);
    }

    const candidates = [...solutions];
    if (poolCandidate && !solutions.some(solution => solution.nonce === poolCandidate.nonce)) {
        candidates.push(poolCandidate);
    }
    self.postMessage({
        type: 'proof',
        data: {
            challenge_id: lease.challenge_id,
            lease_id: lease.lease_id,
            worker_id: lease.worker_id,
            pool_search: poolSearch,
            candidates,
            hashes_attempted: hashesAttempted,
            elapsed_ms: Math.round(performance.now() - startedAt)
        }
    });
}

self.onmessage = async event => {
    if (event.data.type === 'init') {
        try {
            await initializeWasm();
            self.postMessage({ type: 'ready', data: { moduleLoaded: true, variant: wasm.variant } });
        } catch (error) {
            self.postMessage({ type: 'ready', data: { moduleLoaded: false, error: error.message } });
        }
    } else if (event.data.type === 'solve') {
        cancelled = false;
        try {
            await solve(event.data.data, false);
        } catch (error) {
            self.postMessage({ type: 'error', data: error.message || 'Proof solving failed' });
        }
    } else if (event.data.type === 'solve-pool-batch') {
        cancelled = false;
        try {
            await solve(event.data.data, true);
        } catch (error) {
            self.postMessage({
                type: 'error',
                data: error.message || 'Proof solving failed',
                pool_search: true
            });
        }
    } else if (event.data.type === 'cancel-solve') {
        cancelled = true;
    }
};
