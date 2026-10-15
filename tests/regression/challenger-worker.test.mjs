// The browser worker (browser/challenger.js) run against the real WASM
// builds: it picks the SIMD build and falls back to the scalar one, its proof
// carries the first solutions the lease asks for, each rebuilt independently
// into a valid header, a pool search keeps going after them, and a cancel
// stops a search.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { meetsAccessBits, readBuild, sha256d } from './wasm-builds.mjs';

const WORKER_SOURCE = await readFile(new URL('../../browser/challenger.js', import.meta.url), 'utf8');

const LEASE = {
    protocol: 'c2a-work/2',
    challenge_id: 'challenge',
    lease_id: 'lease',
    worker_id: 'worker',
    access_difficulty_bits: 8,
    access_solutions: 16,
    access_work_bits: 12,
    maximum_runtime_seconds: 60,
    pool_target: '00'.repeat(32),
    prev_block_hash: '0123456789abcdef'.repeat(4),
    coinbase_version: 0x20000000,
    coinbase_prefix: '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff20',
    coinbase_suffix: '0000000001000000000000000000000000',
    merkle_branches: ['22'.repeat(32), '33'.repeat(32)],
    extranonce_1: 'aabbccdd',
    extranonce_2: '00000007',
    n_time: 0x65000000,
    n_bits: 0x1703a30c
};

/** Loads a fresh copy of the worker script with a fake worker global. */
async function startWorker(simd) {
    const scalarBytes = await readBuild('scalar');
    const simdBytes = simd === 'served' ? await readBuild('simd')
        : simd === 'unsupported' ? new Uint8Array([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, 0xff]) : null;
    const messages = [];
    const listeners = [];
    globalThis.fetch = async url => {
        const body = url === '/browser/wasm-challenger.wasm' ? scalarBytes
            : url === '/browser/wasm-challenger-simd.wasm' ? simdBytes : null;
        return {
            ok: body !== null,
            status: body === null ? 404 : 200,
            arrayBuffer: async () => body.buffer.slice(body.byteOffset, body.byteOffset + body.byteLength)
        };
    };
    globalThis.self = {
        postMessage(message) {
            messages.push(message);
            for (const listener of listeners.splice(0)) listener();
        }
    };
    // Each run evaluates the script afresh, in its own scope, as a worker would.
    new Function(WORKER_SOURCE)();
    const worker = globalThis.self;
    const send = message => worker.onmessage({ data: message });
    const next = async type => {
        for (;;) {
            const found = messages.find(message => message.type === type);
            if (found) return found;
            await new Promise(resolve => listeners.push(resolve));
        }
    };
    await send({ type: 'init' });
    return { send, next, messages };
}

function independentlyBuiltHeader(lease, nonce) {
    const hex = value => Buffer.from(value, 'hex');
    let root = sha256d(Buffer.concat([
        hex(lease.coinbase_prefix), hex(lease.extranonce_1),
        hex(lease.extranonce_2), hex(lease.coinbase_suffix)
    ]));
    for (const branch of lease.merkle_branches) root = sha256d(Buffer.concat([root, hex(branch)]));
    const previous = hex(lease.prev_block_hash);
    for (let offset = 0; offset < 32; offset += 4) previous.subarray(offset, offset + 4).reverse();
    const header = Buffer.alloc(80);
    header.writeUInt32LE(lease.coinbase_version, 0);
    previous.copy(header, 4);
    root.copy(header, 36);
    header.writeUInt32LE(lease.n_time, 68);
    header.writeUInt32LE(lease.n_bits, 72);
    header.writeUInt32LE(nonce, 76);
    return header;
}

/** The first `count` nonces from 0 whose headers meet `bits`, searched in Node. */
function firstSolutions(lease, bits, count) {
    const nonces = [];
    for (let nonce = 0; nonces.length < count; nonce++) {
        if (meetsAccessBits(sha256d(independentlyBuiltHeader(lease, nonce)), bits)) nonces.push(nonce);
    }
    return nonces;
}

for (const [simd, variant] of [['served', 'simd'], ['missing', 'scalar'], ['unsupported', 'scalar']]) {
    test(`with the SIMD build ${simd}, the worker uses the ${variant} build and its proof verifies`, async () => {
        const worker = await startWorker(simd);
        const ready = await worker.next('ready');
        assert.deepEqual(ready.data, { moduleLoaded: true, variant });

        await worker.send({ type: 'solve', data: LEASE });
        const proof = await worker.next('proof');
        assert.equal(proof.data.challenge_id, 'challenge');
        const { candidates } = proof.data;
        assert.deepEqual(candidates.map(candidate => candidate.nonce),
            firstSolutions(LEASE, LEASE.access_difficulty_bits, LEASE.access_solutions),
            'the proof carries the first sixteen solutions, in order');
        for (const candidate of candidates) {
            assert.equal(candidate.extranonce_2, LEASE.extranonce_2);
            assert.equal(candidate.n_time, LEASE.n_time);
            const hash = sha256d(independentlyBuiltHeader(LEASE, candidate.nonce));
            assert.equal(candidate.header_hash, hash.toString('hex'));
        }
        assert.equal(proof.data.hashes_attempted, candidates.at(-1).nonce + 1,
            'the form search stops at the last solution it needs');
    });
}

test('a lease of the old protocol is refused', async () => {
    const worker = await startWorker('served');
    await worker.next('ready');
    await worker.send({ type: 'solve', data: { ...LEASE, protocol: 'c2a-work/1' } });
    const error = await worker.next('error');
    assert.equal(error.data, 'Invalid proof-of-work assignment');
});

test('a pool search sends its solutions and then the pool share it finds', async () => {
    const worker = await startWorker('served');
    await worker.next('ready');
    // A pool target of 9 zero bits: as with a real pool, every share is also
    // a solution, but not every solution a share.
    await worker.send({ type: 'solve-pool-batch', data: { ...LEASE, pool_target: '007f' + 'ff'.repeat(30) } });
    const proof = await worker.next('proof');
    assert.equal(proof.data.pool_search, true);
    const solutions = firstSolutions(LEASE, LEASE.access_difficulty_bits, LEASE.access_solutions);
    const nonces = proof.data.candidates.map(candidate => candidate.nonce);
    assert.deepEqual(nonces.slice(0, 16), solutions);
    let share = solutions.at(-1) + 1;
    while (!meetsAccessBits(sha256d(independentlyBuiltHeader(LEASE, share)), 9)) share++;
    assert.deepEqual(nonces.slice(16), [share],
        'after the solutions the search goes on to the next pool share');
});

test('a pool search that finds no share still proves its access work', async () => {
    const worker = await startWorker('served');
    await worker.next('ready');
    await worker.send({ type: 'solve-pool-batch', data: { ...LEASE, maximum_runtime_seconds: 1 } });
    const proof = await worker.next('proof');
    assert.deepEqual(proof.data.candidates.map(candidate => candidate.nonce),
        firstSolutions(LEASE, LEASE.access_difficulty_bits, LEASE.access_solutions),
        'the batch still proves its access work');
});

test('a cancel stops a search that has not found a proof', async () => {
    const worker = await startWorker('served');
    await worker.next('ready');
    const solving = worker.send({
        type: 'solve',
        data: { ...LEASE, access_difficulty_bits: 32, maximum_runtime_seconds: 60 }
    });
    const progress = await worker.next('progress');
    assert.ok(progress.data.attempts > 0);
    const cancelledAt = performance.now();
    await worker.send({ type: 'cancel-solve' });
    await solving;
    assert.ok(performance.now() - cancelledAt < 2000, 'the search ends soon after a cancel');
    assert.deepEqual(
        worker.messages.filter(message => message.type === 'proof' || message.type === 'error'),
        []);
});
