// The scalar and SIMD builds of the WASM solver, called through the exports
// every worker uses, return exactly what a one-hash-at-a-time SHA-256d
// search returns. The Rust tests run natively, so this is where the SIMD
// path is checked.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readBuild, referenceSearch, sha256d } from './wasm-builds.mjs';

/** Mulberry32: deterministic, so a failure names a reproducible case. */
function generator(seed) {
    let state = seed >>> 0;
    return () => {
        state = (state + 0x6d2b79f5) >>> 0;
        let value = state;
        value = Math.imul(value ^ (value >>> 15), value | 1);
        value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
        return ((value ^ (value >>> 14)) >>> 0);
    };
}

async function instantiate(name) {
    const { instance } = await WebAssembly.instantiate(await readBuild(name));
    const exports = instance.exports;
    const header = exports.challenger_alloc(80);
    const target = exports.challenger_alloc(32);
    const output = exports.challenger_alloc(84);
    return (headerBytes, targetBytes, bits, start, count, continueAfterAccess) => {
        new Uint8Array(exports.memory.buffer, header, 80).set(headerBytes);
        new Uint8Array(exports.memory.buffer, target, 32).set(targetBytes);
        const error = exports.challenger_search(
            header, target, bits, start, count, continueAfterAccess ? 1 : 0, output);
        assert.equal(error, 0);
        return Buffer.from(new Uint8Array(exports.memory.buffer, output, 84));
    };
}

for (const name of ['scalar', 'simd']) {
    test(`the ${name} build matches the reference search`, async () => {
        const search = await instantiate(name);
        const random = generator(name === 'simd' ? 0x5eed : 0xbeef);
        const bitsChoices = [0, 1, 3, 4, 7, 8, 9, 12, 16, 32, 33, 256];
        for (let index = 0; index < 360; index++) {
            const header = Buffer.alloc(80);
            for (let byte = 0; byte < 80; byte++) header[byte] = random() & 0xff;
            const bits = bitsChoices[index % bitsChoices.length];
            // Counts that are and are not multiples of the four SIMD lanes.
            const count = index % 3 === 0 ? 1 + (random() % 7) : random() % 700;
            const start = index % 6 === 0 ? 0xffffffff - (random() % 9) : random();
            const continueAfterAccess = index % 2 === 0;
            const target = Buffer.alloc(32);
            switch (index % 4) {
                case 1:
                    target.fill(0xff);
                    break;
                case 2: {
                    // The target's first four bytes equal one in-range hash's,
                    // so the remaining bytes decide.
                    for (let byte = 0; byte < 32; byte++) target[byte] = random() & 0xff;
                    const nonce = Math.min(0xffffffff, start + (random() % Math.max(count, 1)));
                    const candidate = Buffer.from(header);
                    candidate.writeUInt32LE(nonce, 76);
                    const hash = sha256d(candidate);
                    target.set([hash[31], hash[30], hash[29], hash[28]], 0);
                    break;
                }
                case 3:
                    for (let byte = 0; byte < 32; byte++) target[byte] = random() & 0xff;
                    target[0] = 0;
                    target[1] &= 0x0f;
                    break;
            }
            const actual = search(header, target, bits, start, count, continueAfterAccess);
            const expected = referenceSearch(header, target, bits, start, count, continueAfterAccess);
            assert.deepEqual(actual, expected,
                `${name} case ${index}: bits ${bits}, start ${start}, count ${count}, ` +
                `continue ${continueAfterAccess}`);
        }
    });
}

test('both builds export the same functions and memory', async () => {
    const exportsOf = async name =>
        WebAssembly.Module.exports(await WebAssembly.compile(await readBuild(name)))
            .map(({ name: exported, kind }) => `${kind}:${exported}`)
            .filter(entry => !entry.startsWith('global:'))
            .sort();
    assert.deepEqual(await exportsOf('simd'), await exportsOf('scalar'));
    assert.deepEqual(
        (await exportsOf('scalar')).filter(entry => entry.startsWith('function:')),
        ['function:challenger_alloc', 'function:challenger_dealloc', 'function:challenger_search']);
});
