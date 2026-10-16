// The demo page's minimal mode (browser/controller.js) driven against a fake
// Challenger and a fake worker: its pool search proves /pool/share-search
// batches, which earn no token, and only once the pool accepts a share does it
// ask for one /forms/contact challenge, whose proof's token submits the form.
// A worker error ends the search instead of leaving it waiting.
import assert from 'node:assert/strict';
import test from 'node:test';
import vm from 'node:vm';
import { readFile } from 'node:fs/promises';

const CONTROLLER_SOURCE = await readFile(new URL('../../browser/controller.js', import.meta.url), 'utf8');
const ORIGIN = 'http://challenger.test';

function element() {
    return {
        hidden: false,
        disabled: false,
        textContent: '',
        title: '',
        style: {},
        attributes: {},
        listeners: {},
        setAttribute(name, value) { this.attributes[name] = value; },
        removeAttribute(name) { delete this.attributes[name]; },
        addEventListener(type, listener) { this.listeners[type] = listener; },
        querySelectorAll() { return []; },
        reportValidity() { return true; },
        reset() {}
    };
}

/**
 * A Challenger that answers like the real one: a token for every proof except
 * a /pool/share-search one, and the pool accepts the share of the batch
 * numbered `acceptedBatch` (from 1).
 */
function fakeChallenger({ acceptedBatch }) {
    const requests = [];
    const resources = new Map();
    let batches = 0;
    let formSubmitted;
    const submitted = new Promise(resolve => { formSubmitted = resolve; });
    const reply = (body, status = 200) => ({
        ok: status < 300,
        status,
        json: async () => body,
        text: async () => JSON.stringify(body)
    });
    const fetch = async (url, options) => {
        const path = url.slice(ORIGIN.length);
        const body = JSON.parse(options.body);
        if (path === '/api/challenge') {
            const challengeId = `challenge-${resources.size + 1}`;
            resources.set(challengeId, body.resource);
            requests.push({ path, resource: body.resource });
            return reply({ challenge_id: challengeId, resource: body.resource });
        }
        if (path === '/api/lease') {
            requests.push({ path, challenge: body.challenge_id });
            return reply({
                protocol: 'c2a-work/2',
                lease_id: `lease-for-${body.challenge_id}`,
                challenge_id: body.challenge_id,
                worker_id: body.worker_id
            });
        }
        if (path === '/api/proof') {
            const resource = resources.get(body.challenge_id);
            const poolShare = body.pool_search && ++batches === acceptedBatch
                ? 'pool_accepted' : 'not_pool_qualified';
            const earnsToken = resource !== '/pool/share-search';
            requests.push({ path, resource, poolShare });
            return reply({
                token: earnsToken ? `token-for-${body.challenge_id}` : null,
                credits_remaining: earnsToken ? 1 : 0,
                expiry: null,
                pool_share: poolShare
            });
        }
        if (path === '/api/forms/contact') {
            requests.push({ path, authorization: options.headers.Authorization });
            formSubmitted();
            return reply({ validated: true, message: 'ok' }, 202);
        }
        throw new Error(`unexpected request ${path}`);
    };
    return { fetch, requests, submitted };
}

/**
 * A worker that answers at once: ready on init, and a proof (or an error)
 * for every solve, flagged as a pool batch the way browser/challenger.js
 * flags it.
 */
function fakeWorkerClass({ failSolve = false } = {}) {
    return class FakeWorker {
        constructor() { this.terminated = false; }
        terminate() { this.terminated = true; }
        postMessage(message) {
            const answer = data => setTimeout(() => {
                if (!this.terminated) this.onmessage({ data });
            }, 0);
            if (message.type === 'init') {
                answer({ type: 'ready', data: { moduleLoaded: true } });
            } else if (failSolve && message.type === 'solve-pool-batch') {
                answer({ type: 'error', data: 'the WASM search failed', pool_search: true });
            } else if (message.type === 'solve' || message.type === 'solve-pool-batch') {
                const poolSearch = message.type === 'solve-pool-batch';
                answer({
                    type: 'proof',
                    data: {
                        challenge_id: message.data.challenge_id,
                        lease_id: message.data.lease_id,
                        worker_id: message.data.worker_id,
                        pool_search: poolSearch,
                        candidates: [],
                        hashes_attempted: 0,
                        elapsed_ms: 0
                    }
                });
            }
        }
    };
}

/** Loads the controller in minimal mode and submits the form. */
function submitInMinimalMode(challenger, Worker) {
    const elements = new Map();
    const documentElement = { classList: { add() {} } };
    const context = vm.createContext({
        window: { location: { origin: ORIGIN, search: '?mode=minimal' } },
        document: {
            documentElement,
            getElementById(id) {
                if (!elements.has(id)) elements.set(id, element());
                return elements.get(id);
            },
            addEventListener() {}
        },
        navigator: { hardwareConcurrency: 1 },
        sessionStorage: { getItem: () => 'worker-1', setItem() {} },
        crypto: { randomUUID: () => 'worker-1' },
        FormData: class { entries() { return [['name', 'A'], ['email', 'a@example.test'], ['message', 'Hi']]; } },
        URLSearchParams,
        Worker,
        fetch: challenger.fetch,
        performance,
        setTimeout,
        setInterval,
        clearInterval,
        console: { error() {}, log() {} }
    });
    vm.runInContext(CONTROLLER_SOURCE, context);
    const controller = vm.runInContext('controller', context);
    controller.init();
    elements.get('contact-form').listeners.submit({ preventDefault() {} });
    return { controller, button: elements.get('submit-form') };
}

async function settle(condition, what) {
    for (let waited = 0; waited < 2000; waited += 5) {
        if (condition()) return;
        await new Promise(resolve => setTimeout(resolve, 5));
    }
    assert.fail(`timed out waiting for ${what}`);
}

test('minimal mode searches without tokens and earns one form token after the pool accepts a share', async () => {
    const challenger = fakeChallenger({ acceptedBatch: 3 });
    const { button } = submitInMinimalMode(challenger, fakeWorkerClass());
    await Promise.race([
        challenger.submitted,
        new Promise((_, reject) => setTimeout(() => reject(new Error('the form was never submitted')), 2000))
    ]);
    await settle(() => button.textContent.startsWith('Submitted in'), 'the submitted label');

    const challenges = challenger.requests.filter(request => request.path === '/api/challenge');
    assert.deepEqual(
        challenges.map(request => request.resource),
        ['/pool/share-search', '/pool/share-search', '/pool/share-search', '/forms/contact'],
        'three token-free batches, then one form challenge'
    );
    const accepted = challenger.requests.findIndex(request => request.poolShare === 'pool_accepted');
    const formChallenge = challenger.requests.findIndex(request => request.resource === '/forms/contact');
    assert.ok(accepted >= 0 && formChallenge > accepted, 'the form challenge comes after the accepted share');
    const proofs = challenger.requests.filter(request => request.path === '/api/proof');
    assert.equal(proofs.filter(proof => proof.resource === '/forms/contact').length, 1);
    const submission = challenger.requests.find(request => request.path === '/api/forms/contact');
    assert.equal(submission.authorization, 'Bearer token-for-challenge-4');
});

test('a worker error ends the minimal-mode search with a retry', async () => {
    const challenger = fakeChallenger({ acceptedBatch: 1 });
    const { controller, button } = submitInMinimalMode(challenger, fakeWorkerClass({ failSolve: true }));
    await settle(() => button.textContent === 'Search failed - retry', 'the retry label');
    assert.equal(controller.poolSearchActive, false);
    assert.match(button.title, /the WASM search failed/);
    assert.equal(challenger.requests.some(request => request.path === '/api/forms/contact'), false);
});
