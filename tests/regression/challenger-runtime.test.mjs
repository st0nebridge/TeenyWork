import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

test('browser uses the server 60-second proof window instead of cutting off at 10 seconds', async () => {
    const worker = await readFile(new URL('../../browser/challenger.js', import.meta.url), 'utf8');

    assert.match(worker, /const MAX_SOLVE_RUNTIME_MS = 60_000;/);
    assert.match(worker, /Math\.min\(MAX_SOLVE_RUNTIME_MS, lease\.maximum_runtime_seconds \* 1000\)/);
    assert.doesNotMatch(worker, /Math\.min\(10000,/);
});
