/**
 * @module wasm-builds
 * @description Locates the two release builds of the WASM solver for the Node
 * tests, and a reference SHA-256d search to hold them to.
 *
 * @input The workspace's cargo target directory.
 * @output Module bytes for the scalar and SIMD builds; reference search helpers.
 * @dependencies node:fs, node:crypto
 */
import { readFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';

const ROOT = new URL('../../', import.meta.url);

export const BUILDS = {
    scalar: {
        path: 'target/wasm32-unknown-unknown/release/c2a_challenger.wasm',
        command: 'cargo build --release -p c2a-challenger --target wasm32-unknown-unknown'
    },
    simd: {
        path: 'target/wasm-simd/wasm32-unknown-unknown/release/c2a_challenger.wasm',
        command: 'RUSTFLAGS="-C target-feature=+simd128" cargo build --release -p c2a-challenger ' +
            '--target wasm32-unknown-unknown --target-dir target/wasm-simd'
    }
};

export async function readBuild(name) {
    const build = BUILDS[name];
    try {
        return await readFile(new URL(build.path, ROOT));
    } catch (error) {
        throw new Error(`The ${name} WASM solver is not built (${build.path}); build it with: ${build.command}`);
    }
}

export function sha256d(bytes) {
    return createHash('sha256').update(createHash('sha256').update(bytes).digest()).digest();
}

export function meetsAccessBits(hash, bits) {
    const whole = Math.floor(bits / 8);
    for (let index = 0; index < whole; index++) {
        if (hash[31 - index] !== 0) return false;
    }
    return bits % 8 === 0 || (hash[31 - whole] >> (8 - bits % 8)) === 0;
}

export function meetsTarget(hash, target) {
    for (let index = 31; index >= 0; index--) {
        if (hash[index] < target[31 - index]) return true;
        if (hash[index] > target[31 - index]) return false;
    }
    return true;
}

/** The 84-byte result `challenger_search` writes, computed one hash at a time. */
export function referenceSearch(header, target, bits, start, count, continueAfterAccess) {
    const candidate = Buffer.from(header);
    let attempted = 0;
    let access = null;
    let pool = null;
    for (let offset = 0; offset < count; offset++) {
        const nonce = start + offset;
        if (nonce > 0xffffffff) break;
        candidate.writeUInt32LE(nonce, 76);
        const hash = sha256d(candidate);
        attempted++;
        if (!access && meetsAccessBits(hash, bits)) {
            access = [nonce, hash];
            if (!continueAfterAccess) break;
        }
        if (!pool && meetsTarget(hash, target)) {
            pool = [nonce, hash];
            break;
        }
    }
    const output = Buffer.alloc(84);
    output.writeUInt32LE(attempted, 0);
    if (access) {
        output.writeUInt32LE(1, 4);
        output.writeUInt32LE(access[0], 8);
        access[1].copy(output, 12);
    }
    if (pool) {
        output.writeUInt32LE(1, 44);
        output.writeUInt32LE(pool[0], 48);
        pool[1].copy(output, 52);
    }
    return output;
}
