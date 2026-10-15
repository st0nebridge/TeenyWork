/**
 * @module miner-throughput
 * @description Measures the WASM solver builds' hash rate through the same
 * export the browser worker calls, alternating builds round by round so
 * background load affects them alike.
 *
 * @input Optional: seconds per round, rounds, and extra .wasm files to compare
 * (for example an older build): node tests/bench/miner-throughput.mjs 1 10 old.wasm
 * @output One line per build: best and median MH/s, and the median paired
 * ratio to the first build listed.
 * @dependencies ../regression/wasm-builds.mjs; the scalar and SIMD release builds.
 */
import { readFile } from 'node:fs/promises';
import { readBuild } from '../regression/wasm-builds.mjs';

const [secondsArg = '1', roundsArg = '10', ...extraPaths] = process.argv.slice(2);
const seconds = Number(secondsArg);
const rounds = Number(roundsArg);

async function solver(name, bytes) {
    const { instance } = await WebAssembly.instantiate(bytes);
    const { memory, challenger_alloc, challenger_search } = instance.exports;
    const header = challenger_alloc(80);
    const target = challenger_alloc(32);
    const output = challenger_alloc(84);
    const view = new Uint8Array(memory.buffer);
    for (let index = 0; index < 80; index++) view[header + index] = (index * 37 + 11) & 0xff;
    view.fill(0, target, target + 32);
    let nonce = 0;
    return {
        name,
        rates: [],
        round() {
            const startedAt = performance.now();
            let hashed = 0;
            while (performance.now() - startedAt < seconds * 1000) {
                // 256 access bits and a zero target: nothing is found, every nonce is hashed.
                challenger_search(header, target, 256, nonce, 16384, 1, output);
                const count = new DataView(memory.buffer, output, 4).getUint32(0, true);
                hashed += count;
                nonce = (nonce + count) >>> 0;
            }
            this.rates.push(hashed / ((performance.now() - startedAt) / 1000) / 1e6);
        }
    };
}

const solvers = [];
for (const path of extraPaths) {
    solvers.push(await solver(path.split(/[\\/]/).pop(), await readFile(path)));
}
solvers.push(await solver('scalar build', await readBuild('scalar')));
solvers.push(await solver('simd build', await readBuild('simd')));

for (const each of solvers) each.round();
for (const each of solvers) each.rates.length = 0;
for (let round = 0; round < rounds; round++) {
    for (const each of round % 2 ? [...solvers].reverse() : solvers) each.round();
}

const median = values => [...values].sort((a, b) => a - b)[values.length >> 1];
const [base] = solvers;
for (const each of solvers) {
    const ratio = median(each.rates.map((rate, index) => rate / base.rates[index]));
    console.log(`${each.name.padEnd(24)} best ${Math.max(...each.rates).toFixed(3)} MH/s, ` +
        `median ${median(each.rates).toFixed(3)} MH/s, ${ratio.toFixed(2)}x ${base.name}`);
}
